#ifndef BRUTEFORCE_DES_HPP_
# define BRUTEFORCE_DES_HPP_

#include <fstream>
#include <experimental/string_view>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include "concurrency/Threadpool.hpp"

namespace Bruteforce
{
    class DES
    {
    public:
        using Threadpool = tea::concurrency::Threadpool;
        using BoolFuture = std::future<bool>;

        typedef struct {
            bool                        debug;
            bool                        stats;
            unsigned int                nb_threads;
            std::string                 salt;
            std::string                 encrypted_key;
            std::vector<std::string>    dictionaries;
        } Config;

    public:
        DES();
        DES(DES const& other) = delete;
        ~DES();

        DES&        operator=(DES const& other) = delete;
        bool        run(Config const& config, std::string& key);

        static bool is_valid_config(Config const& config,
                                    std::string* err) noexcept;
        static void is_valid_config(Config const& config);

    protected:
        void            init_stats();
        unsigned int    attempts_producer();
        unsigned int    extract_words(std::ifstream& dict);
        bool            bruteforce_bulk(std::vector<std::string> const& bulk);

        template<typename R>
        static bool
        is_future_ready(std::future<R> const& f)
        {
            return f.wait_for(std::chrono::seconds(0))
                    == std::future_status::ready;
        }

    protected:
        Config const*               _config;
        std::string*                _key;
        std::unique_ptr<Threadpool> _threadpool;
        std::vector<BoolFuture>     _futures;
        std::mutex                  _mutex;

        // stats
        unsigned int                _attempts;
        std::vector<size_t>         _dicts_sizes;
        size_t                      _attempts_size;

        static const size_t         buffer_size;
        static const unsigned int   timeout;
    };

    std::ostream&
    operator<<(std::ostream& lhs, Bruteforce::DES::Config const& rhs);
}


#endif /* end of include guard: BRUTEFORCE_DES_HPP_ */
