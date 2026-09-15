find_library(DL_LIBRARY dl)

set(TEST_PROGS prog_access
               prog_access2
               prog_chmod
               prog_chown
               prog_concurrent
               prog_create
               prog_fchmod
               prog_fchown
               prog_fstat
               prog_fallocate
               prog_ftruncate
               prog_lchmod
               prog_lchown
               prog_link
               prog_lseek
               prog_lstat
               prog_mkdir
               prog_mknod
               prog_mount
               prog_open_read
               prog_open_write
               prog_opendir
               prog_parse_url_full
               prog_read_update_pos
               prog_rename
               prog_rmdir
               prog_stat
               prog_statvfs
               prog_symlink
               prog_timeout
               prog_truncate
               prog_unlink
               prog_utimes
               prog_zdr_alignment)

foreach(TARGET ${TEST_PROGS})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} nfs)
endforeach()

add_test(NAME zdr_alignment COMMAND prog_zdr_alignment)

add_library(ld_timeout SHARED ld_timeout.c)
set_target_properties(ld_timeout PROPERTIES PREFIX "")
target_link_libraries(ld_timeout nfs ${DL_LIBRARY})

set(UNIT_TEST_PROGS prog_nfs4_delay prog_nfs4_errno prog_nfs4_object prog_nfs4_slots)

foreach(TARGET ${UNIT_TEST_PROGS})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} nfs)
  add_test(NAME ${TARGET} COMMAND ${TARGET})
endforeach()

set_tests_properties(prog_nfs4_object PROPERTIES SKIP_RETURN_CODE 77)
set_tests_properties(prog_nfs4_slots PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 15)

add_executable(prog_nfs4_recovery prog_nfs4_recovery.c)
target_link_libraries(prog_nfs4_recovery nfs)
foreach(SCENARIO renew-ok renew-delay renew-lost reboot-renew rebind-ok reboot-rebind active-lost
                 renew-delay-repeat renew-delay-reconnect renew-delay-destroy
                 renew-lost-credentials active-lost-credentials renew-lost-open active-lost-read
                 renew-lost-lock active-lost-repeat active-lost-concurrent
                 recovery-cancel recovery-destroy recovery-create-delay recovery-create-delay-reconnect
                 lost-mutation-reply reboot-open reboot-active-read reboot-open-credentials
                 reboot-open-no-grace reboot-open-stale reboot-dirty-open reboot-fsynced-open
                 reboot-no-grace-delay reboot-no-grace-stale reboot-no-grace-session-loss
                 reboot-no-grace-reboot reboot-no-grace-complete-loss reboot-no-grace-close
                 reboot-no-grace-destroy reboot-no-grace-threaded reboot-reclaim-bad reboot-reclaim-conflict
                 reboot-lock-lost reboot-new-open reboot-rejected-mutation reboot-active-write
                 reboot-open-other-uid reboot-reclaim-delay reboot-create-long-delay reboot-post-grace
                 commit-verifier-change reboot-threaded-read reboot-new-open-after-loss
                 reboot-reclaim-destroy reboot-reclaim-close reboot-reclaim-session-loss
                 reboot-reclaim-reboot reboot-held-repeat)
  add_test(NAME nfs4_recovery_${SCENARIO} COMMAND prog_nfs4_recovery ${SCENARIO})
  set_tests_properties(nfs4_recovery_${SCENARIO} PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 25)
endforeach()

file(GLOB TESTS test_*.sh)

file(COPY functions.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

foreach(TEST ${TESTS})
  file(COPY ${TEST} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
  add_test(NAME ${TEST}
           COMMAND ${TEST}
           WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endforeach()

add_executable(prog_zdr_bytes_zero prog_zdr_bytes_zero.c)
target_link_libraries(prog_zdr_bytes_zero nfs)
add_test(NAME zdr_bytes_zero COMMAND prog_zdr_bytes_zero)
