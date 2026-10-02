# Install script for directory: /repo/Pass_GPL/asuswrt/release/src/router/getdns

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "MinSizeRel")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "TRUE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/repo/Pass_GPL/asuswrt/release/src/router/getdns/build/libgetdns.a")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE DIRECTORY FILES "/repo/Pass_GPL/asuswrt/release/src/router/getdns/build/getdns")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/man" TYPE DIRECTORY FILES "/repo/Pass_GPL/asuswrt/release/src/router/getdns/build/man3")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/getdns" TYPE FILE FILES
    "/repo/Pass_GPL/asuswrt/release/src/router/getdns/AUTHORS"
    "/repo/Pass_GPL/asuswrt/release/src/router/getdns/ChangeLog"
    "/repo/Pass_GPL/asuswrt/release/src/router/getdns/COPYING"
    "/repo/Pass_GPL/asuswrt/release/src/router/getdns/LICENSE"
    "/repo/Pass_GPL/asuswrt/release/src/router/getdns/NEWS"
    "/repo/Pass_GPL/asuswrt/release/src/router/getdns/README.md"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/getdns/spec" TYPE FILE FILES "/repo/Pass_GPL/asuswrt/release/src/router/getdns/spec/index.html")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" TYPE FILE FILES "/repo/Pass_GPL/asuswrt/release/src/router/getdns/build/getdns.pc")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  message("***
***  !!! IMPORTANT !!!!
***
***  From release 1.2.0, getdns comes with built-in DNSSEC
***  trust anchor management.  External trust anchor management,
***  for example with unbound-anchor, is no longer necessary
***  and no longer recommended.
***
***  Previously installed trust anchors, in the default location -
***
***        /etc/unbound/getdns-root.key
***
***  - will be preferred and used for DNSSEC validation, however
***  getdns will fallback to trust-anchors obtained via built-in
***  trust anchor management when the anchors from the default
***  location fail to validate the root DNSKEY rrset.
***
***  To prevent expired DNSSEC trust anchors to be used for
***  validation, we strongly recommend removing the trust anchors
***  on the default location when there is no active external
***  trust anchor management keeping it up-to-date.
***")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/repo/Pass_GPL/asuswrt/release/src/router/getdns/build/stubby/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/repo/Pass_GPL/asuswrt/release/src/router/getdns/build/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
