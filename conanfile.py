from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps
from os import environ

class GigamonkeyConan (ConanFile):
    name = "gigamonkey"
    version = "v0.0.15"
    license = "Open BSV"
    author = "Daniel Krawisz"
    url = "https://github.com/Gigamonkey-BSV/Gigamonkey"
    description = "Bitcoin and Bitcoin protocols, including Boost POW and Stratum"
    topics = ("Bitcoin", "Boost POW", "Stratum")
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}
    exports_sources = "CMakeLists.txt", "include/*", "src/*", "test/*"
    requires = [
        "boost/1.80.0", 
        "openssl/1.1.1t", 
        "cryptopp/8.5.0", 
        "nlohmann_json/3.11.2", 
        "gmp/6.2.1", 
        "secp256k1/0.3@proofofwork/stable", 
        "data/v0.0.26@proofofwork/stable",
        "gtest/1.12.1"
    ]
    
    def set_version (self):
        if "CIRCLE_TAG" in environ:
            self.version = environ.get ("CIRCLE_TAG")[1:]
        if "CURRENT_VERSION" in environ:
            self.version = environ['CURRENT_VERSION']
        else:
            self.version = "v0.0.14"

    def config_options (self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure_cmake (self):
        cmake = CMake (self)
        cmake.configure(variables={"PACKAGE_TESTS":"Off"})
        return cmake
    
    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.generate()

    def build (self):
        cmake = self.configure_cmake ()
        cmake.build ()

    def package (self):
        cmake = CMake(self)
        cmake.install()

    def package_info (self):
#        self.cpp_info.libdirs = ["lib"]  # Default value is 'lib'
        self.cpp_info.libs = ["gigamonkey"]
