#include <cstdlib>
#include <cxxopts.hpp>
#include "BruteforceDES.hpp"

static bool
parse_options(int ac, char** av, Bruteforce::DES::Config& config)
{
    try {
        cxxopts::Options options(av[0],
                                 " - a bruteforce tool for DES encryption");

        options.add_options()
            ("h,help", "display help")
            ("d,debug", "run with debug mode")
            ("t,threads", "number of threads", cxxopts::value<unsigned int>())
            ("s,salt", "salt", cxxopts::value<std::string>())
            ("e,encrypted-key", "encrypted key", cxxopts::value<std::string>())
            ("dictionaries",
             "dictionary files, can be entered without this option",
             cxxopts::value<std::vector<std::string>>())
        ;

        options.parse(ac, av);
        options.parse_positional(std::vector<std::string>(1, "dictionaries"));
        if (options.count("help"))
        {
            std::cout << options.help() << std::endl;
            exit(EXIT_SUCCESS);
        }
        config.debug = options.count("debug");
        config.nb_threads = options["threads"].as<unsigned int>();
        config.salt = options["salt"].as<std::string>();
        config.encrypted_key = options["encrypted-key"].as<std::string>();
        if (options.count("dictionaries")) {
            config.dictionaries =
                options["dictionaries"].as<std::vector<std::string>>();
        }
    } catch (cxxopts::OptionException const& e) {
        std::cerr << e.what() << std::endl;
        return false;
    }
    return true;
}

int
main(int ac, char** av)
{
    Bruteforce::DES::Config     config;

    if (not parse_options(ac, av, config)) {
        return EXIT_FAILURE;
    }
    std::cout << config << std::endl;
    return EXIT_SUCCESS;
}
