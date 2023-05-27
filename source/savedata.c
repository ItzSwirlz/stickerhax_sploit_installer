#include <3ds.h>
#include <stdlib.h>
FS_Archive save_archive;
Handle save_session;

Result read_savedata(const char* path, void** data, size_t* size) {
    if(!path || !data || !size) return -1;

    Handle file;
    Result ret = -1;
    void* buffer = NULL;
    
    fsUseSession(save_session);
    u32 pathData[3] = { MEDIATYPE_SD, 0x000a5e00, 0x00040000};
    const FS_Path pathl = {PATH_BINARY, 12, (const void*)pathData};
    
    // First, open the archive
    ret = FSUSER_OpenArchive(&save_archive, ARCHIVE_SAVEDATA, pathl);
    if(ret) printf("failed to open archive %08lX\n", ret);
    
    // Now, open the file
    ret = FSUSER_OpenFile(&file, save_archive, fsMakePath(PATH_ASCII, path), FS_OPEN_READ, 0);
     if(ret) printf("failed to open file%08lX\n", ret);

    // Create a buffer to read it
    u64 file_size = 0;
    ret = FSFILE_GetSize(file, &file_size);
     if(ret) printf("failed to get size%08lX\n", ret);
    buffer = malloc(file_size);

    // Read the file
    u32 bytes_read = 0;
    ret = FSFILE_Read(file, &bytes_read, 0, buffer, file_size);
     if(ret) printf("failed to read file %08lX\n", ret);

    // Close the file
    ret = FSFILE_Close(file);
     if(ret) printf("failed to close file\n");

    fsEndUseSession();
    return ret;
}

Result write_savedata(const char* path, const void* data, size_t size) {
    if(!path || !data || size == 0) return -1;

    Result ret = -1;
    int fail = 0;
    
    fsUseSession(save_session);
    u32 pathData[3] = { MEDIATYPE_SD, 0x000a5e00, 0x00040000};
    const FS_Path pathl = {PATH_BINARY, 12, (const void*)pathData};

    ret = FSUSER_OpenArchive(&save_archive, ARCHIVE_SAVEDATA, pathl);
     if(ret) printf("failed to open archive%08lX\n", ret);

    // delete file
    FSUSER_DeleteFile(save_archive, fsMakePath(PATH_ASCII, "/payload.bin"));
     if(ret) printf("failed to delete save archive%08lX\n", ret);
    FSUSER_ControlArchive(save_archive, ARCHIVE_ACTION_COMMIT_SAVE_DATA, NULL, 0, NULL, 0);
     if(ret) printf("failed to control archive%08lX\n", ret);

    Handle file;
    ret = FSUSER_OpenFile(&file, save_archive, fsMakePath(PATH_ASCII, path), FS_OPEN_CREATE | FS_OPEN_WRITE, 0);
     if(ret) printf("failed to open file%08lX\n", ret);

    u32 bytes_written = 0;
    ret = FSFILE_Write(file, &bytes_written, 0x0, data, size, FS_WRITE_FLUSH | FS_WRITE_UPDATE_TIME);
     if(ret) printf("failed to write file%08lX\n", ret);

    ret = FSFILE_Close(file);
     if(ret) printf("failed to close file%08lX\n", ret);
    ret = FSUSER_ControlArchive(save_archive, ARCHIVE_ACTION_COMMIT_SAVE_DATA, NULL, 0, NULL, 0);
     if(ret) printf("failed to control archive 2nd time%08lX\n", ret);

    fsEndUseSession();
    return ret;
}