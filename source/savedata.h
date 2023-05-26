#include <3ds.h>
#include <stdlib.h>
extern Handle save_session;

Result read_savedata(const char* path, void** data, size_t* size);
Result write_savedata(const char* path, const void* data, size_t size);