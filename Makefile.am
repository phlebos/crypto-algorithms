ACLOCAL_AMFLAGS = -I m4 --install

bin_PROGRAMS = sha256_test bcmine generate_first_hash hello			
sha256_test_SOURCES = src/sha256_test.c src/sha256.c src/sha256.h
bcmine_SOURCES = src/bcmine.c src/sha256.c src/sha256.h 
generate_first_hash_SOURCES = src/generate_first_hash.c src/sha256.c src/sha256.h 
#bcmine_LDADD=libgmp.la
hello_SOURCES = src/hello.c

EXTRA_DIST = m4/notes
