#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#include <3ds.h>

#include "filesystem.h"
#include "blz.h"

char status[256];

char regionids_table[7][4] = {//http://3dbrew.org/wiki/Nandrw/sys/SecureInfo_A
"JPN",
"USA",
"EUR",
"JPN", //"AUS"
"CHN",
"KOR",
"TWN"
};

struct {
	bool enabled;
	size_t offset;
	char path[256];
} payload_embed;

struct {
	struct {
		bool enabled;
		u32 directories;
		u32 files;
		u32 directoryBuckets;
		u32 fileBuckets;
		bool duplicateData;
	} saveformat;

	char versiondir[64];
	char displayversion[64];
} exploit_titleconfig;

Result read_savedata(const char* path, void** data, size_t* size)
{
	if(!path || !data || !size)return -1;

	Result ret;
	int fail = 0;

	Handle inFileHandle;
	u32 bytesRead;
	u64 inFileSize = 0;
	void* buffer = NULL;

	disableHBLHandle();

	ret = FSUSER_OpenFile(&inFileHandle, saveGameArchive, fsMakePath(PATH_ASCII, path), FS_OPEN_READ, 0);
	if(ret){fail = -8; goto readFail;}

	FSFILE_GetSize(inFileHandle, &inFileSize);

	buffer = malloc(inFileSize);
	if(!buffer){fail = -9; goto readFail;}

	ret = FSFILE_Read(inFileHandle, &bytesRead, 0, buffer, inFileSize);
	if(ret){fail = -10; goto readFail;}

	FSFILE_Close(inFileHandle);

	readFail:
	if(fail)
	{
		sprintf(status, "failed to read from file : %d\n     %08X %08X", fail, (unsigned int)ret, (unsigned int)bytesRead);
		if(buffer)free(buffer);
	}
	else
	{
		sprintf(status, "successfully read from file\n	 %08X              ", (unsigned int)bytesRead);
		*data = buffer;
		*size = bytesRead;
	}

	enableHBLHandle();

	return ret;
}

Result write_savedata(char* path, u8* data, u32 size)
{
	if(!path || !data || !size)return -1;

	Handle outFileHandle;
	u32 bytesWritten;
	Result ret = 0;
	int fail = 0;

	disableHBLHandle();
	u32 pathData[3] = {MEDIATYPE_SD, 0x000a5e00, 0x00040000};
	const FS_Path pathl = {PATH_BINARY, 12, (const void*)pathData};

	ret = FSUSER_OpenArchive(&saveGameArchive, ARCHIVE_USER_SAVEDATA, pathl);
    if(R_FAILED(ret))
    {
        fail = -1;
        goto writeFail;
    }

    // delete file
    FSUSER_DeleteFile(saveGameArchive, fsMakePath(PATH_ASCII, path));
    FSUSER_ControlArchive(saveGameArchive, ARCHIVE_ACTION_COMMIT_SAVE_DATA, NULL, 0, NULL, 0);

    Handle file = 0;
    ret = FSUSER_OpenFile(&file, saveGameArchive, fsMakePath(PATH_ASCII, path), FS_OPEN_CREATE | FS_OPEN_WRITE, 0);
    if(R_FAILED(ret))
    {
        fail = -2;
        goto writeFail;
    }

    u32 bytes_written = 0;
    ret = FSFILE_Write(file, &bytes_written, 0, data, size, FS_WRITE_FLUSH | FS_WRITE_UPDATE_TIME);
    if(R_FAILED(ret))
    {
        fail = -3;
        goto writeFail;
    }

    ret = FSFILE_Close(file);
    if(R_FAILED(ret))
    {
        fail = -4;
        goto writeFail;
    }

    ret = FSUSER_ControlArchive(saveGameArchive, ARCHIVE_ACTION_COMMIT_SAVE_DATA, NULL, 0, NULL, 0);
    if(R_FAILED(ret)) fail = -5;

    writeFail:
    FSUSER_CloseArchive(saveGameArchive);
    fsEndUseSession();
    if(fail) sprintf(status, "An error occured! Failed to write to file: %d\n     %08lX %08lX", fail, ret, bytes_written);
    else sprintf(status, "Successfully wrote to file!\n     %08lX               ", bytes_written);

    return ret;
}

typedef enum
{
	STATE_NONE,
	STATE_INITIALIZE,
	STATE_INITIAL,
	STATE_SELECT_SLOT,
	STATE_LOAD_PAYLOAD,
	STATE_COMPRESS_PAYLOAD,
	STATE_INSTALL_PAYLOAD,
	STATE_INSTALLED_PAYLOAD,
	STATE_ERROR,
}state_t;

void remove_newline(char *line)
{
	int len = strlen(line);
	if(len==0)return;

	if(line[len-1]=='\n')
	{
		line[len-1] = 0;
		if(len>1)
		{
			if(line[len-2]=='\r')
			{
				line[len-2] = 0;
			}
		}
	}
}

//Format of the config file: each line is for a different exploit. Each parameter is seperated by spaces(' '). "<exploitname> <titlename> <flags_bitmask> <list_of_programIDs>"
Result load_exploitlist_config(char *filepath, u64 *cur_programid, char *out_exploitname, char *out_titlename, unsigned int *out_flags_bitmask)
{
	FILE *f;
	int len;
	int ret = 2;
	u64 config_programid;
	char *strptr;
	char *exploitname, *titlename;
	char line[256];

	f = fopen(filepath, "r");
	if(f==NULL)return 1;

	memset(line, 0, sizeof(line));
	while(fgets(line, sizeof(line)-1, f))
	{
		remove_newline(line);

		len = strlen(line);
		if(len==0)continue;

		strptr = strtok(line, " ");
		if(strptr==NULL)continue;
		exploitname = strptr;

		strptr = strtok(NULL, " ");
		if(strptr==NULL)continue;
		titlename = strptr;

		strptr = strtok(NULL, " ");
		if(strptr==NULL)continue;
		*out_flags_bitmask = 0;
		sscanf(strptr, "0x%x", out_flags_bitmask);

		while((strptr = strtok(NULL, " ")))
		{
			config_programid = 0;
			sscanf(strptr, "%016llx", &config_programid);
			if(config_programid==0)continue;

			if(*cur_programid == config_programid)
			{
				ret = 0;
				break;
			}
		}

		if(ret==0)break;
	}

	fclose(f);

	if(ret==0)
	{
		strncpy(out_exploitname, exploitname, 63);
		strncpy(out_titlename, titlename, 63);
	}

	return ret;
}

Result load_exploitconfig(char *exploitname, u64 *cur_programid, u32 app_remaster_version, u16 *update_titleversion, u32 *installed_remaster_version)
{
	FILE *f;
	int len;
	int ret = 2;
	int stage = 0;
	unsigned int tmpver, tmpremaster;

	unsigned int directories=0;
	unsigned int files=0;
	unsigned int directoryBuckets=0;
	unsigned int fileBuckets=0;
	unsigned int duplicateData=1;

	char *strptr;
	char *namestr = NULL, *valuestr = NULL;
	char filepath[256];
	char line[256];

	if(update_titleversion==NULL)
	{
		*installed_remaster_version = app_remaster_version;
		stage = 2;
		ret = 5;
	}

	memset(filepath, 0, sizeof(filepath));

	snprintf(filepath, sizeof(filepath)-1, "romfs:/%s/%016llx/config.ini", exploitname, *cur_programid);

	f = fopen(filepath, "r");
	if(f==NULL)return 1;

	memset(line, 0, sizeof(line));
	while(fgets(line, sizeof(line)-1, f))
	{
		remove_newline(line);

		len = strlen(line);
		if(len==0)continue;

		if(stage==1 || stage==3 || stage==5)
		{
			if(line[0]=='[' && line[len-1]==']')break;

			strptr = strtok(line, "=");
			if(strptr==NULL)continue;
			namestr = strptr;

			strptr = strtok(NULL, "=");
			if(strptr==NULL)continue;
			valuestr = strptr;
		}

		if(stage==0)
		{
			if(strcmp(line, "[updatetitle_versions]")==0)
			{
				ret = 3;
				stage = 1;
			}
		}
		else if(stage==1)
		{
			tmpver = 0;
			tmpremaster = 0;
			if(sscanf(namestr, "v%u", &tmpver)==1)
			{
				if(sscanf(valuestr, "%04X", &tmpremaster)==1)
				{
					if(tmpver == *update_titleversion)
					{
						if(app_remaster_version < tmpremaster)
						{
							*installed_remaster_version = tmpremaster;
						}
						else
						{
							*installed_remaster_version = app_remaster_version;
						}

						ret = 4;
						stage = 2;
						fseek(f, 0, SEEK_SET);
					}
				}
			}
		}
		else if(stage==2)
		{
			if(strcmp(line, "[remaster_versions]")==0)
			{
				ret = 5;
				stage = 3;
			}
		}
		else if(stage==3)
		{
			tmpremaster = 0;
			if(sscanf(namestr, "%04X", &tmpremaster)==1)
			{
				if(*installed_remaster_version == tmpremaster)
				{
					ret = 4;
					strptr = strtok(valuestr, "@");
					if(strptr==NULL)break;

					strncpy(exploit_titleconfig.versiondir, strptr, 63);

					strptr = strtok(NULL, "@");
					if(strptr==NULL)break;
					strncpy(exploit_titleconfig.displayversion, strptr, 63);

					ret = 0;

					stage = 4;
					fseek(f, 0, SEEK_SET);
				}
			}
		}
		else if(stage==4)
		{
			if(strcmp(line, "[config]")==0)
			{
				stage = 5;
			}
		}
		else if(stage==5)
		{
			if(strcmp(namestr, "saveformat")==0)
			{
				if(sscanf(valuestr, "%u,%u,%u,%u,%u", &directories, &files, &directoryBuckets, &fileBuckets, &duplicateData)==5)
				{
					exploit_titleconfig.saveformat.enabled = true;

					exploit_titleconfig.saveformat.directories = directories;
					exploit_titleconfig.saveformat.files = files;
					exploit_titleconfig.saveformat.directoryBuckets = directoryBuckets;
					exploit_titleconfig.saveformat.fileBuckets = fileBuckets;
					exploit_titleconfig.saveformat.duplicateData = duplicateData;

					break;
				}
			}
		}
	}

	fclose(f);

	return ret;
}

Result convert_filepath(char *inpath, char *outpath, u32 outpath_maxsize, int selected_slot)
{
	char *strptr = NULL;
	char *convstr = NULL;
	char tmpstr[8];
	char tmpstr2[16];

	strptr = strtok(inpath, "@");

	while(strptr)
	{
		convstr = &strptr[strlen(strptr)+1];

		strncat(outpath, strptr, outpath_maxsize-1);

		if(convstr[0]!='!')
		{
			strptr = strtok(NULL, "@");
			continue;
		}

		switch(convstr[1])
		{
			case 'd':
			{
				if(convstr[2] < '0' || convstr[2] > '9') return 9;

				memset(tmpstr, 0, sizeof(tmpstr));
				memset(tmpstr2, 0, sizeof(tmpstr2));
				snprintf(tmpstr, sizeof(tmpstr) - 1, "%s%c%c", "%0", convstr[2], convstr[1]);
				snprintf(tmpstr2, sizeof(tmpstr2) - 1, tmpstr, selected_slot);

				strncat(outpath, tmpstr2, outpath_maxsize - 1);

				strptr = strtok(&convstr[3], "@");
				break;
			}

			case 'p':
			{
				char tmpstr3[9];
				for(int i = 0; i < 8; i++)
				{
					tmpstr3[i] = convstr[i + 2];
					if(!isxdigit(tmpstr3[i])) return 9;
				}

				payload_embed.offset = strtol(tmpstr3, NULL, 16);
				payload_embed.enabled = true;

				strptr = strtok(&convstr[10], "@");
				strncpy(payload_embed.path, outpath, sizeof(payload_embed.path) - 1);
				break;
			}

			default: return 9;
		}
	}

	return 0;
}

Result parsecopy_saveconfig(char *versiondir, u32 type, int selected_slot)
{
	FILE *f, *fsave;
	int fd=0;
	int len;
	int ret = 2;
	u8 *savebuffer;
	u32 savesize;
	char *strptr;
	char *namestr, *valuestr;
	u32 tmpval=0;
	struct stat filestats;
	char line[256];
	char tmpstr[256];
	char tmpstr2[256];
	char savedir[256];

	memset(savedir, 0, sizeof(savedir));
	memset(tmpstr, 0, sizeof(tmpstr));

	if(type<2)
	{
		snprintf(savedir, sizeof(savedir)-1, "%s/%s", versiondir, type==0?"Old3DS":"New3DS");
	}
	else
	{
		snprintf(savedir, sizeof(savedir)-1, "%s/%s", versiondir, "common");
	}

	snprintf(tmpstr, sizeof(tmpstr)-1, "%s/%s", savedir, "config.ini");

	f = fopen(tmpstr, "r");
	if(f==NULL)return 1;

	memset(line, 0, sizeof(line));
	while(fgets(line, sizeof(line)-1, f))
	{
		remove_newline(line);

		len = strlen(line);
		if(len==0)continue;

		strptr = strtok(line, "=");
		if(strptr==NULL)break;
		namestr = strptr;

		strptr = strtok(NULL, "=");
		if(strptr==NULL)break;
		valuestr = strptr;

		memset(tmpstr2, 0, sizeof(tmpstr2));

		ret = convert_filepath(namestr, tmpstr2, sizeof(tmpstr2), selected_slot);
		if(ret)break;

		memset(tmpstr, 0, sizeof(tmpstr));
		snprintf(tmpstr, sizeof(tmpstr)-1, "%s/%s", savedir, tmpstr2);

		fsave = fopen(tmpstr, "r");
		if(fsave==NULL)
		{
			ret = 3;
			break;
		}

		fd = fileno(fsave);
		if(fd==-1)
		{
			fclose(fsave);
			ret = errno;
			break;
		}

		if(fstat(fd, &filestats)==-1)
		{
			fclose(fsave);
			ret = errno;
			break;
		}

		savesize = filestats.st_size;
		if(savesize==0)
		{
			fclose(fsave);
			ret = 4;
			break;
		}

		savebuffer = malloc(savesize);
		if(savebuffer==NULL)
		{
			fclose(fsave);
			ret = 5;
			break;
		}

		tmpval = fread(savebuffer, 1, savesize, fsave);
		fclose(fsave);
		if(tmpval!=savesize)
		{
			ret = 6;
			free(savebuffer);
			break;
		}

		memset(tmpstr2, 0, sizeof(tmpstr2));

		ret = convert_filepath(valuestr, tmpstr2, sizeof(tmpstr2), selected_slot);
		if(ret)
		{
			free(savebuffer);
			break;
		}

		ret = write_savedata(tmpstr2, savebuffer, savesize);
		free(savebuffer);

		if(ret)break;
	}

	fclose(f);

	return ret;
}

int main()
{

	gfxInitDefault();
	gfxSet3D(false);

	filesystemInit();

	PrintConsole topConsole, bttmConsole;
	consoleInit(GFX_TOP, &topConsole);
	consoleInit(GFX_BOTTOM, &bttmConsole);

	consoleSelect(&topConsole);
	consoleClear();

	state_t current_state = STATE_NONE;
	state_t next_state = STATE_INITIALIZE;

	static char top_text[2048];
	char top_text_tmp[256];
	top_text[0] = '\0';

	int selected_slot = 0;
	u32 selected_remaster_version = 0;

	int firmware_version[6];
	int firmware_selected_value = 0;
	int firmware_maxnum;

	int pos;

	u8* payload_buf = NULL;
	u32 payload_size = 0;

	u32 cur_processid = 0;
	u64 cur_programid = 0;
	u64 cur_programid_update = 0;
	u8 update_mediatype = 1;
	u32 updatetitle_entry_valid = 0;
	FS_ProductInfo cur_productinfo;
	AM_TitleEntry title_entry;

	u64 menu_programid = 0;
	AM_TitleEntry menu_title_entry;

	bool sysinfo_overridden = false, allow_use_menuver = false;

	OS_VersionBin nver_versionbin, cver_versionbin;
	u8 region=0;
	bool new3dsflag = 0;

	unsigned int flags_bitmask = 0;

	char exploitname[64] = "stickerhax";
	char titlename[64] = "Sticker-Star";
	char useragent[64];

	memset(firmware_version, 0, sizeof(firmware_version));

	memset(exploitname, 0, sizeof(exploitname));
	memset(titlename, 0, sizeof(titlename));

	memset(&exploit_titleconfig, 0, sizeof(exploit_titleconfig));

	while (aptMainLoop())
	{
		hidScanInput();
		if(hidKeysDown() & KEY_START)break;

		// transition function
		if(next_state != current_state)
		{
			memset(top_text_tmp, 0, sizeof(top_text_tmp));

			switch(next_state)
			{
				case STATE_INITIALIZE:
					strncat(top_text, " Initializing... You may press START at any time\nto return to menu.\n", sizeof(top_text)-1);
					break;
				case STATE_INITIAL:
					strncat(top_text, " Welcome to the stickerhax_sploit_installer ! Please proceedwith caution, as you might lose data if you don't.\n                            Press A to continue.\n\n", sizeof(top_text)-1);
					break;
				case STATE_SELECT_SLOT:
					snprintf(top_text_tmp, sizeof(top_text_tmp)-1, " Please select the savegame slot %s will be\ninstalled to. D-Pad to select, A to continue.\n", exploitname);
					break;
				case STATE_LOAD_PAYLOAD:
					strncat(top_text, " Reading payload... \n", sizeof(top_text)-1);
					break;
				case STATE_COMPRESS_PAYLOAD:
					strncat(top_text, " Processing payload...\n", sizeof(top_text)-1);
					break;
				case STATE_INSTALL_PAYLOAD:
					strncat(top_text, " Installing payload...\n", sizeof(top_text)-1);
					break;
				case STATE_INSTALLED_PAYLOAD:
					snprintf(top_text_tmp, sizeof(top_text_tmp)-1, " Done ! %s was successfully installed.", exploitname);
					break;
				case STATE_ERROR:
					strncat(top_text, " Looks like something went wrong. :(\n", sizeof(top_text)-1);
					break;
				default:
					break;
			}

			if(top_text_tmp[0])strncat(top_text, top_text_tmp, sizeof(top_text)-1);

			current_state = next_state;
		}

		consoleSelect(&topConsole);
		printf("\x1b[0;%dHsploit_installer", (50 - 17) / 2);
		printf("\x1b[1;%dHby smea and yellows8\n\n\n", (50 - 7) / 2);
		printf(top_text);

		// state function
		switch(current_state)
		{
			case STATE_INITIALIZE:
				{
					Result ret = osGetSystemVersionData(&nver_versionbin, &cver_versionbin);
					if(R_FAILED(ret))
					{
						snprintf(status, sizeof(status)-1, "Failed to get the system-version.\n    Error code : %08X", (unsigned int)ret);
						next_state = STATE_ERROR;
						break;
					}

					ret = cfguInit();
					if(R_FAILED(ret))
					{
						snprintf(status, sizeof(status)-1, "Failed to initialize cfgu.\n    Error code : %08X", (unsigned int)ret);
						next_state = STATE_ERROR;
						break;
					}

					ret = CFGU_SecureInfoGetRegion(&region);
					if(R_FAILED(ret))
					{
						snprintf(status, sizeof(status)-1, "Failed to get the system region.\n    Error code : %08X", (unsigned int)ret);
						next_state = STATE_ERROR;
						break;
					}

					cfguExit();

					APT_CheckNew3DS(&new3dsflag);

					firmware_version[0] = new3dsflag;
					firmware_version[5] = region;

					firmware_version[1] = cver_versionbin.mainver;
					firmware_version[2] = cver_versionbin.minor;
					firmware_version[3] = cver_versionbin.build;
					firmware_version[4] = nver_versionbin.mainver;

					ret = svcGetProcessId(&cur_processid, 0xffff8001);
					if(R_FAILED(ret))
					{
						snprintf(status, sizeof(status)-1, "Failed to get the processID for the current process.\n    Error code : %08X", (unsigned int)ret);
						next_state = STATE_ERROR;
						break;
					}

					ret = FSUSER_GetProductInfo(&cur_productinfo, cur_processid);

					if(R_FAILED(ret))
					{
						snprintf(status, sizeof(status)-1, "Failed to get the ProductInfo for the current process.\n    Error code : %08X", (unsigned int)ret);
						next_state = STATE_ERROR;
						break;
					}

					ret = APT_GetProgramID(&cur_programid);

					if(R_FAILED(ret))
					{
						snprintf(status, sizeof(status)-1, "Failed to get the programID for the current process.\n    Error code : %08X", (unsigned int)ret);
						next_state = STATE_ERROR;
						break;
					}

					if(((cur_programid >> 32) & 0xffff) == 0)cur_programid_update = cur_programid | 0x0000000e00000000ULL;//Only set the update-title programid when the cur_programid is for a regular application title.

					if(cur_programid_update)
					{
						ret = amInit();
						if(R_FAILED(ret))
						{
							snprintf(status, sizeof(status)-1, "Failed to initialize AM.\n    Error code : %08X", (unsigned int)ret);
							next_state = STATE_ERROR;
							break;
						}

						ret = AM_GetTitleInfo(update_mediatype, 1, &cur_programid_update, &title_entry);
						amExit();
						if(ret==0)
						{
							updatetitle_entry_valid = 1;
						}
					}


					ret = romfsInit();
					if(ret)
					{
						snprintf(status, sizeof(status)-1, "Failed to initialize romfs for this application(romfsInit()).\n    Error code : %08X", (unsigned int)ret);
						next_state = STATE_ERROR;
						break;
					}

					//ret = load_exploitconfig(exploitname, &cur_programid, cur_productinfo.remasterVersion, updatetitle_entry_valid ? &title_entry.version:NULL, &selected_remaster_version);
					// if(ret)
					// {
					// 	snprintf(status, sizeof(status)-1, "Failed to find your version of\n%s in the config / config loading failed.\n    Error code : %08X", titlename, (unsigned int)ret);
					// 	if(ret==1)strncat(status, " Failed to\nopen the config file in romfs.", sizeof(status)-1);
					// 	if(ret==2 || ret==4)strncat(status, " The romfs config file is invalid.", sizeof(status)-1);
					// 	if(ret==3)
					// 	{
					// 		snprintf(status, sizeof(status)-1, "this update-title version(v%u) of %s is not compatible with %s, sorry\n", title_entry.version, titlename, exploitname);
					// 		next_state = STATE_ERROR;
					// 		break;
					// 	}
					// 	if(ret==5)
					// 	{
					// 		snprintf(status, sizeof(status)-1, "this remaster-version(%04X) of %s is not compatible with %s, sorry\n", (unsigned int)selected_remaster_version, titlename, exploitname);
					// 		next_state = STATE_ERROR;
					// 		break;
					// 	}

					// 	next_state = STATE_ERROR;
				//		break;
					//}
					flags_bitmask = 0x4;
					exploit_titleconfig.saveformat.enabled = true;
					exploit_titleconfig.saveformat.directories = 0;
					exploit_titleconfig.saveformat.files = 4;
					exploit_titleconfig.saveformat.directoryBuckets = 3;
					exploit_titleconfig.saveformat.fileBuckets = 5;
					exploit_titleconfig.saveformat.duplicateData = 0;
					
					sprintf(exploit_titleconfig.versiondir, "romfs:/stickerhax/00040000000a5e00/v1.0");
					sprintf(exploit_titleconfig.displayversion, "1.0");
					
					ret = amInit();
					if(ret==0)ret = APT_GetAppletInfo(APPID_HOMEMENU, &menu_programid, NULL, NULL, NULL, NULL);
					if(ret==0)ret = AM_GetTitleInfo(MEDIATYPE_NAND, 1, &menu_programid, &menu_title_entry);
					amExit();

					if(ret==0)allow_use_menuver = true;

					next_state = STATE_INITIAL;
				}
				break;
			case STATE_INITIAL:
				if(hidKeysDown() & KEY_A)next_state = STATE_SELECT_SLOT;
				break;
			case STATE_SELECT_SLOT:
				{
					if(hidKeysDown() & KEY_UP)selected_slot++;
					if(hidKeysDown() & KEY_DOWN)selected_slot--;
					if(hidKeysDown() & KEY_A)next_state = STATE_LOAD_PAYLOAD;

					if(selected_slot < 0) selected_slot = 0;
					if(selected_slot > 2) selected_slot = 2;

					printf((selected_slot >= 2) ? "                                             \n" : "                                            ^\n");
					printf("                            Selected slot : %d  \n", selected_slot + 1);
					printf((!selected_slot) ? "                                             \n" : "                                            v\n");
				}
				break;
			case STATE_LOAD_PAYLOAD:
				// Gruetzig's code in basehaxx_sploit_installer
				FILE* file = fopen("sdmc:/payload.bin", "r");
                sprintf(top_text_tmp, "Using payload from SD");
                if (file == NULL) {
                    sprintf(status, "\nFailed to open otherapp payload\n");
                    next_state = STATE_ERROR;
                    break;
                }
                fseek(file, 0, SEEK_END);
                payload_size = ftell(file);
                fseek(file, 0, SEEK_SET);

                payload_buf = malloc(payload_size);
                if(!payload_buf) {
                    next_state = STATE_ERROR;
                    fclose(file);
                    break;
                }
 
                fread(payload_buf, payload_size, 1, file);
                fclose(file);
                next_state = STATE_COMPRESS_PAYLOAD;;
				break;
			case STATE_COMPRESS_PAYLOAD:
				payload_buf = BLZ_Code(payload_buf, payload_size, (unsigned int*)&payload_size, BLZ_NORMAL);
				next_state = STATE_INSTALL_PAYLOAD;
				break;
			case STATE_INSTALL_PAYLOAD:
				{
					if(exploit_titleconfig.saveformat.enabled)//This block is based on code from salt_sploit_installer.
					{
	u32 pathData[3] = {MEDIATYPE_SD, 0x000A5E00, 0x00040000};
	const FS_Path pathl = {PATH_BINARY, 12, (const void*)pathData};
						
						disableHBLHandle();
						Result ret = FSUSER_FormatSaveData(ARCHIVE_SAVEDATA, (FS_Path)pathl, 0x200, exploit_titleconfig.saveformat.directories, exploit_titleconfig.saveformat.files, exploit_titleconfig.saveformat.directoryBuckets, exploit_titleconfig.saveformat.fileBuckets, exploit_titleconfig.saveformat.duplicateData);
						FSUSER_ControlArchive(saveGameArchive, ARCHIVE_ACTION_COMMIT_SAVE_DATA, NULL, 0, NULL, 0);
						enableHBLHandle();
						filesystemExit();
						filesystemInit();
						if(ret)
						{
							sprintf(status, "Failed to format savedata.\n    Error code: %08lX", ret);
							next_state = STATE_ERROR;
							break;
						}
					}
					if(flags_bitmask & 0x2)
					{
						Result ret = parsecopy_saveconfig(exploit_titleconfig.versiondir, firmware_version[0], selected_slot);
						if(ret)
						{
							sprintf(status, "Failed to install the savefile(s) with romfs %s savedir.\n    Error code : %08X", firmware_version[0]==0?"Old3DS":"New3DS", (unsigned int)ret);
							next_state = STATE_ERROR;
							break;
						}
					}

					if(flags_bitmask & 0x4)
					{
						Result ret = parsecopy_saveconfig(exploit_titleconfig.versiondir, 2, selected_slot);
						if(ret)
						{
							sprintf(status, "Failed to install the savefile(s) with romfs %s savedir.\n    Error code : %08X", "common", (unsigned int)ret);
							next_state = STATE_ERROR;
							break;
						}
					}
				}

				{
					// delete file
					disableHBLHandle();
					FSUSER_DeleteFile(saveGameArchive, fsMakePath(PATH_ASCII, "/payload.bin"));

					FSUSER_ControlArchive(saveGameArchive, ARCHIVE_ACTION_COMMIT_SAVE_DATA, NULL, 0, NULL, 0);
					enableHBLHandle();
				}

				{
					Result ret;

					if(payload_embed.enabled)
					{
						void* buffer = NULL;
						size_t size = 0;
						ret = read_savedata(payload_embed.path, &buffer, &size);
						if(ret)
						{
							sprintf(status, "Failed to embed payload\n    Error code : %08X", (unsigned int)ret);
							next_state = STATE_ERROR;
							break;
						}
						if((payload_embed.offset + payload_size + sizeof(u32)) >= size)
						{
							sprintf(status, "Failed to embed payload (too large)\n    0x%lX >= 0x%X", (payload_embed.offset + payload_size + sizeof(u32)), size);
							next_state = STATE_ERROR;
							break;
						}

						*(u32*)(buffer + payload_embed.offset) = payload_size;
						memcpy(buffer + payload_embed.offset + sizeof(u32), payload_buf, payload_size);
						ret = write_savedata(payload_embed.path, buffer, size);

						free(buffer);
					}
					else
						ret = write_savedata("/payload.bin", payload_buf, payload_size);

					if(ret)
					{
						sprintf(status, "Failed to install payload\n    Error code : %08X", (unsigned int)ret);
						next_state = STATE_ERROR;
						break;
					}

					next_state = STATE_INSTALLED_PAYLOAD;
				}
				break;
			case STATE_INSTALLED_PAYLOAD:
				next_state = STATE_NONE;
				break;
			default:
				break;
		}

		consoleSelect(&bttmConsole);
		printf("\x1b[0;0H  Current status :\n    %s\n", status);

		gspWaitForVBlank();
	}

	romfsExit();

	filesystemExit();

	gfxExit();
	return 0;
}
