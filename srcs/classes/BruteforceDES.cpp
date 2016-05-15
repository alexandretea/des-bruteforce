#include <stdexcept>
#include <fstream>
#include "BruteforceDES.hpp"

namespace Bruteforce
{
    /*
    ** Constructor/Destructor
    */
    DES::DES() : _threadpool(nullptr), _key(nullptr)
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
        _threadpool = std::make_unique<Threadpool>(config.nb_threads);
        for (auto& dict_path: config.dictionaries) {
            std::ifstream   dict(dict_path.c_str());

            if (dict) {
                extract_words(dict);
            } else {
                std::cerr << "Warning: can't read from dictionary: "
                          << dict_path << std::endl;
            }
        }
        return true;
    }

    /*
    ** Private member functions
    */
    void
    DES::extract_words(std::ifstream& dict) {
        using   string_view = std::experimental::string_view;
        char    buffer[DES::buffer_size];

        while (not dict.eof()) {
            unsigned int                i = 0;
            std::string                 left;
            std::vector<std::string>    bulk;

            dict.read(buffer, DES::buffer_size);
            buffer[dict.gcount()] = '\0';

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
                for (auto& a: bulk) {
                    std::cout << a << std::endl;
                }
                // _threadpool( , std::move(bulk));
            }
        }
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
