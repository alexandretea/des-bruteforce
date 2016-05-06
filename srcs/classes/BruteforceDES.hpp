#ifndef BRUTEFORCE_DES_HPP_
# define BRUTEFORCE_DES_HPP_

#include <experimental/string_view>
#include <iostream>

namespace Bruteforce
{
    class DES
    {
    public:
        using string_view = std::experimental::string_view;

    public:
        typedef struct {
            bool                        debug;
            unsigned int                nb_threads;
            std::string                 salt;
            std::string                 encrypted_key;
            std::vector<std::string>    dictionaries;
        } Config;

    public:
    };
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

#endif /* end of include guard: BRUTEFORCE_DES_HPP_ */
