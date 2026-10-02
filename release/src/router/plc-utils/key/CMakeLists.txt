# ====================================================================
# programs;
# --------------------------------------------------------------------

add_executable(hpavkey hpavkey.c)
add_executable(hpavkeys hpavkeys.c)
add_executable(rkey rkey.c)
add_executable(mac2pw mac2pw.c)
add_executable(mac2pwd mac2pwd.c)

# ====================================================================
# dependencies;
# --------------------------------------------------------------------

target_link_libraries(hpavkey key tools)
target_link_libraries(hpavkeys key tools)
target_link_libraries(mac2pw key tools)
target_link_libraries(mac2pwd key tools)
target_link_libraries(rkey key tools)

# ====================================================================
# libraries;
# --------------------------------------------------------------------

add_library(key HPAVKeySHA.c SHA256Reset.c SHA256Block.c SHA256Write.c SHA256Fetch.c HPAVKeyNMK.c HPAVKeyOut.c HPAVKeyNID.c HPAVKeyDAK.c HPAVKeySpec.c MACPasswords.c keys.c)

