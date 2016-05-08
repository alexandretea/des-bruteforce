#ifndef BRUTEFORCE_DES_HPP_
# define BRUTEFORCE_DES_HPP_

#include <experimental/string_view>
#include <iostream>
#include <vector>
#include <string>

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
        DES();
        DES(DES const& other) = delete;
        ~DES();

    public:
        DES&    operator=(DES const& other) = delete;

    public:
        bool    run(Config const& config, std::string& key);

    public:
        static bool is_valid_config(Config const& config,
                                    std::string* err) noexcept;
        static void is_valid_config(Config const& config);

    protected:
        Config  _config;
    };
}

std::ostream&
operator<<(std::ostream& lhs, Bruteforce::DES::Config const& rhs);

#endif /* end of include guard: BRUTEFORCE_DES_HPP_ */
