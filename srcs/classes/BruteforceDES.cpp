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
        _config = config;
        std::cout << "DES bruteforce running with following configuration:"
                  << std::endl << _config;
        (void)key;
        return true;
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
