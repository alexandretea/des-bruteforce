#include <unistd.h>
#include <stdexcept>
#include <fstream>
#include <cstring>
#include <crypt.h>
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
        std::packaged_task<unsigned int ()>
            reader_task(std::bind(&DES::attempts_producer, this));

        std::future<unsigned int>   reader_future = reader_task.get_future();
        std::thread                 dict_reader(std::move(reader_task));

        bool        found(false);

        do {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(DES::timeout)
            );

            {
                std::lock_guard<std::mutex> lock(_mutex);

                for (auto it = _futures.begin(); it != _futures.end();) {
                    if (it->valid() and DES::is_future_ready(*it)) {
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
            if (_config->stats) {
                std::cout << "Attempts: " << _attempts << "/"
                          << _attempts_size << std::endl;
            }
        } while (not found
                 and (not _futures.empty()
                      or not is_future_ready(reader_future)));
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

    unsigned int
    DES::attempts_producer()
    {
        unsigned int nb_words = 0;

        try {

            for (auto& dict_path: _config->dictionaries) {
                std::ifstream   dict(dict_path.c_str());

                if (dict) {
                    std::cout << "dict: " << dict_path << std::endl;
                    nb_words = extract_words(dict);
                } else {
                    std::cerr << "Warning: can't read from dictionary: "
                    << dict_path << std::endl;
                }
            }
        } catch (std::exception const& e) {
            std::cerr << "An error occured while extracting from dictionaries: "
                      << e.what() << std::endl;
        }
        return nb_words;
    }

    unsigned int
    DES::extract_words(std::ifstream& dict) {
        using string_view = std::experimental::string_view;

        char            buffer[DES::buffer_size + 1];
        unsigned int    nb_words = 0;

        while (not dict.eof()) {
            unsigned int                i = 0;
            std::string                 left;
            std::vector<std::string>    bulk;

            dict.read(buffer, DES::buffer_size);
            if (dict.gcount() == 0)
                break ;
            buffer[dict.gcount()] = '\0';

            string_view buff_view(buffer, dict.gcount());

            while (i < buff_view.size()) {
                unsigned long   pos = buff_view.find('\n', i);

                if (pos == string_view::npos) {
                    left = buff_view.data() + i;
                    i = buff_view.size();
                } else if (pos == 0) {
                    ++i;
                } else {
                    std::string     word(buff_view.data() + i,
                                         buff_view.data() + pos - 1);

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

                nb_words += bulk.size();
                _futures.emplace_back(
                    _threadpool->push(std::bind(&DES::bruteforce_bulk, this,
                                            std::placeholders::_1),
                                      std::move(bulk))
                );
            }
        }
        return nb_words;
    }

    bool
    DES::bruteforce_bulk(std::vector<std::string> const& bulk)
    {
        static std::mutex  mutex;

        try {
            char const* encrypted;

            for (auto& attempt: bulk) {
                struct crypt_data   data;

                data.initialized = 0;
                if ((encrypted = ::crypt_r(attempt.data(), _config->salt.data(),
                                           &data)) == NULL) {
                    std::cerr << "Warning: crypt() failed (salt: '"
                              << _config->salt << "', key: '" << attempt << "')"
                              << std::endl;
                }
                if (_config->encrypted_key == std::string(encrypted + 2)) {
                    *_key = attempt;
                    return true;
                }
                if (_config->stats) {
                    static std::mutex           mutex;
                    std::lock_guard<std::mutex> lock(mutex);

                    ++_attempts;
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
