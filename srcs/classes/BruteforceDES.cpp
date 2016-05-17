#include <unistd.h>
#include <stdexcept>
#include <fstream>
#include "BruteforceDES.hpp"

namespace Bruteforce
{
    /*
    ** Static variables
    */
    const size_t         DES::buffer_size = 4096; // bytes
    const unsigned int   DES::timeout     = 1000; // milliseconds

    /*
    ** Constructor/Destructor
    */
    DES::DES() :
        _config(nullptr), _key(nullptr), _threadpool(nullptr)
    {
    }

    DES::~DES()
    {
    }

    /*
    ** Public member functions
    */
    bool
    DES::run(Config const& config, std::string& key)
    {
        is_valid_config(config);
        std::cout << "DES bruteforce running with following configuration:"
                  << std::endl << config;
        _key = &key;
        _config = &config;
        if (_config->stats) {
            init_stats();
        }
        _threadpool = std::make_unique<Threadpool>(config.nb_threads);

        std::thread dict_reader(std::bind(&DES::attempts_producer, this));
        bool        found(false);

        do {
            if (_config->stats) {
                std::cout << "Attempts: " << _attempts << std::endl;
            }
            std::this_thread::sleep_for(
                std::chrono::milliseconds(DES::timeout)
            );

            {
                std::lock_guard<std::mutex> lock(_mutex);

                for (auto it = _futures.begin(); it != _futures.end();) {
                    if (it->valid()) {
                        ++_attempts;
                        if (it->get()) {
                            found = true;
                            break ;
                        } else {
                            it = _futures.erase(it);
                            continue ;
                        }
                    }
                    ++it;
                }
            }
        } while (not found
                 and not _futures.empty()
                 and _threadpool->unsafe_pending_tasks() > 0);
        dict_reader.join();
        return found;
    }

    /*
    ** Protected member functions
    */
    void
    DES::init_stats()
    {
        _attempts = 0;
        _dicts_sizes.resize(_config->dictionaries.size(), 0);
        _attempts_size = 0;
        for (unsigned int i = 0; i < _config->dictionaries.size(); ++i) {
            std::ifstream in(_config->dictionaries.at(i),
                             std::ifstream::ate | std::ifstream::binary);

            _dicts_sizes[i] = (in.tellg() != -1
                               ? static_cast<size_t>(in.tellg()) : 0);
            _attempts_size += _dicts_sizes[i];
        }
    }

    void
    DES::attempts_producer()
    {
        try {
            for (auto& dict_path: _config->dictionaries) {
                std::ifstream   dict(dict_path.c_str());

                if (dict) {
                    extract_words(dict);
                } else {
                    std::cerr << "Warning: can't read from dictionary: "
                    << dict_path << std::endl;
                }
            }
        } catch (std::exception const& e) {
            std::cerr << "An error occured while extracting from dictionaries: "
                      << e.what() << std::endl;
        }
    }

    void
    DES::extract_words(std::ifstream& dict) {
        using   string_view = std::experimental::string_view;
        char    buffer[DES::buffer_size + 1];

        while (not dict.eof()) {
            unsigned int                i = 0;
            std::string                 left;
            std::vector<std::string>    bulk;

            dict.read(buffer, DES::buffer_size);
            buffer[dict.gcount()] = '\0';

            if (dict.gcount() == 0)
                continue ;
            string_view buff_view(buffer, dict.gcount());

            while (i < buff_view.size()) {
                unsigned long   pos = buff_view.find('\n', i);

                if (pos == string_view::npos) {
                    left = buff_view.data() + i;
                    i = buff_view.size();
                } else {
                    std::string     word(buff_view.data() + i,
                                         buff_view.data() + pos);

                    if (not word.empty())
                        bulk.emplace_back(std::move(word));
                    if (not bulk.empty() and not left.empty()) {
                        bulk.back().insert(0, left);
                        left.clear();
                    }
                    i = pos + 1;
                }
            }
            if (not bulk.empty()) {
                std::lock_guard<std::mutex> lock(_mutex);

                _futures.emplace_back(
                    _threadpool->push(std::bind(&DES::bruteforce_bulk, this,
                                            std::placeholders::_1),
                                      std::move(bulk))
                );
            }
        }
    }

    bool
    DES::bruteforce_bulk(std::vector<std::string> const& bulk)
    {
        try {
            char const* encrypted;

            for (auto& attempt: bulk) {
                if ((encrypted =
                    ::crypt(attempt.data(), _config->salt.data())) == NULL) {
                    std::cerr << "Warning: crypt() failed (salt: '"
                              << _config->salt << "', key: '" << attempt << "')"
                              << std::endl;
                } else if (_config->encrypted_key == encrypted + 2) {
                    *_key = attempt;
                    return true;
                }
            }
        } catch (std::exception const& e) {
            std::cerr << "An error occured while bruteforcing: "
                      << e.what() << std::endl;
        }
        return false;
    }

    /*
    ** Static functions
    */
    bool
    DES::is_valid_config(Config const& config, std::string* err) noexcept
    {
        if (config.nb_threads == 0) {
            if (err != nullptr)
                *err = "Number of thread can't be 0";
            return false;
        } else if (config.salt.empty()) {
            if (err != nullptr)
                *err = "Salt can't be empty";
            return false;
        } else if (config.encrypted_key.empty()) {
             if (err != nullptr)
                *err = "Encrypted key can't be empty";
             return false;
        } else if (config.dictionaries.empty()) {
            if (err != nullptr)
                *err = "You have to provide at least one dictionary";
            return false;
        }
        return true;
    }

    void
    DES::is_valid_config(Config const& config)
    {
        std::string err;

        if (not is_valid_config(config, &err)) {
            #warning "switch to ConfigException"
            throw std::runtime_error(err);
        }
    }

    /*
    ** Misc
    */
    std::ostream&
    operator<<(std::ostream& lhs, Bruteforce::DES::Config const& rhs)
    {
        lhs << "Debug:\t\t\t" << (rhs.debug ? "Yes" : "No") << std::endl
            << "Stats:\t\t\t" << (rhs.stats ? "Yes" : "No") << std::endl
            << "Number of threads:\t" << rhs.nb_threads << std::endl
            << "Salt:\t\t\t" << rhs.salt << std::endl
            << "Encrypted key:\t\t" << rhs.encrypted_key << std::endl
            << "Dictionaries:" << std::endl;
        for (auto& path: rhs.dictionaries) {
            lhs << "\t" << path << std::endl;
        }
        return lhs;
    }
}
