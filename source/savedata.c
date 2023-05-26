#include <3ds.h>
#include <stdlib.h>
FS_Archive *save_archive;

Result read_savedata(const char* path, void** data, size_t* size) {
    if(!path || !data || !size) return -1;

    Handle file = 0;
    Result ret = -1;
    void* buffer = NULL;
    
    fsUseSession(0);
    u32 pathData[3] = { MEDIATYPE_SD, 0x000a5e00, 0x00040000};
    const FS_Path pathl = {PATH_BINARY, 12, (const void*)pathData};
    
    // First, open the archive
    ret = FSUSER_OpenArchive(&save_archive, ARCHIVE_USER_SAVEDATA, pathl);
    
    // Now, open the file
    ret = FSUSER_OpenFile(&file, save_archive, fsMakePath(PATH_ASCII, path), FS_OPEN_READ, 0);

    // Create a buffer to read it
    u64 file_size = 0;
    ret = FSFILE_GetSize(file, &file_size);
    buffer = malloc(file_size);

    // Read the file
    u32 bytes_read = 0;
    ret = FSFILE_Read(file, &bytes_read, 0, buffer, file_size);

    // Close the file
    ret = FSFILE_Close(file);
    return ret;
}

Result write_savedata(const char* path, const void* data, size_t size) {
    if(!path || !data || size == 0) return -1;

    Result ret = -1;
    int fail = 0;
    
    fsUseSession(0);
    u32 pathData[3] = { MEDIATYPE_SD, 0x000a5e00, 0x00040000};
    const FS_Path pathl = {PATH_BINARY, 12, (const void*)pathData};

    ret = FSUSER_OpenArchive(&save_archive, ARCHIVE_USER_SAVEDATA, pathl);

    // delete file
    FSUSER_DeleteFile(save_archive, fsMakePath(PATH_ASCII, path));
    FSUSER_ControlArchive(save_archive, ARCHIVE_ACTION_COMMIT_SAVE_DATA, NULL, 0, NULL, 0);

    Handle file = 0;
    ret = FSUSER_OpenFile(&file, save_archive, fsMakePath(PATH_ASCII, path), FS_OPEN_CREATE | FS_OPEN_WRITE, 0);

    u32 bytes_written = 0;
    ret = FSFILE_Write(file, &bytes_written, 0, data, size, FS_WRITE_FLUSH | FS_WRITE_UPDATE_TIME);

    ret = FSFILE_Close(file);
    ret = FSUSER_ControlArchive(save_archive, ARCHIVE_ACTION_COMMIT_SAVE_DATA, NULL, 0, NULL, 0);

    return ret;
}