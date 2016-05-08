#include <stdexcept>
#include "BruteforceDES.hpp"

namespace Bruteforce
{
    /*
    ** Constructor/Destructor
    */
    DES::DES()
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
        _config = config;
        std::cout << "DES bruteforce running with following configuration:"
                  << std::endl << _config;
        (void)key;
        return true;
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
            throw std::runtime_error(err); // switch to ConfigException
        }
    }
}

std::ostream&
operator<<(std::ostream& lhs, Bruteforce::DES::Config const& rhs)
{
    lhs << "Debug:\t\t\t" << (rhs.debug ? "Yes" : "No") << std::endl
        << "Number of threads:\t" << rhs.nb_threads << std::endl
        << "Salt:\t\t\t" << rhs.salt << std::endl
        << "Encrypted key:\t\t" << rhs.encrypted_key << std::endl
        << "Dictionaries:" << std::endl;
    for (auto& path: rhs.dictionaries) {
        lhs << "\t" << path << std::endl;
    }
    return lhs;
}
