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
        options.parse_positional("dictionaries");
        options.parse(ac, av);
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
    try {
        Bruteforce::DES::Config     config;
        Bruteforce::DES             bruteforcer;
        std::string                 key;

        if (not parse_options(ac, av, config)) {
            return EXIT_FAILURE;
        }
        if (bruteforcer.run(config, key)) {
            std::cout << "Key found: " << key << std::endl;
        } else {
            std::cout << "Key not found" << std::endl;
        }
    } catch (std::exception const& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "An unexpected internal error occured" << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
