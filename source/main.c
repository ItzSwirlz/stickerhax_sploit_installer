#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <3ds.h>
#include <stdlib.h>
#include "savedata.h"
#include "blz.h"

int main()
{
	u8* payload_buffer = NULL;
    u32 payload_size = 0;
	
	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);
	
	Result rc = romfsInit();
	if (rc)
		printf("romfsInit: %08lX\n", rc);
	else
	{
		printf("romfs Init Successful!\n");
	}
	
	printf("Let's get started! First lets find the title ID you're on. Since this is still in development, I'll assume the game is on the sd card\n");
	u64 *ext_data_id;
	//Result title_id_result = AM_GetTitleExtDataId(ext_data_id, MEDIATYPE_SD, 0x00040000000a5e00);
	/*if(title_id_result) {
		printf("Failed to get the title ID.\n");
		sleep(5000);
		romfsExit();
		gfxExit();
		return 0;
	}
	*/
	printf("Cool, got it, let me find your otherapp payload on your SD card\n");
	FILE* otherapp_payload = fopen("sdmc:/otherapp.bin", "r");
	if(otherapp_payload == NULL) {
		printf("I couldn't find it. Make sure your otherapp payload is on the root of the sdcard and is named 'otherapp.bin'\n");
		sleep(5000);
		romfsExit();
		gfxExit();
		return 0;
	}
	
	// from basehaxx sploit installer
	fseek(otherapp_payload, 0, SEEK_END);
    payload_size = ftell(otherapp_payload);
    fseek(otherapp_payload, 0, SEEK_SET);

    payload_buffer = malloc(payload_size);
    if(!payload_buffer) {
    	fclose(otherapp_payload);
    }

	fread(payload_buffer, payload_size, 1, otherapp_payload);
	fclose(otherapp_payload);

	printf("Done! Now lets read your save file.\n");
	payload_buffer = BLZ_Code(payload_buffer, payload_size, (unsigned int*)&payload_size, BLZ_NORMAL);

    void* buffer = NULL;
    size_t size = 0;
	Result read_ret = read_savedata("/main", &buffer, &size);
	
	u32 out_size = 0;
	char path[256];
	memset(path, 0, sizeof(path));

	Result write_ret = write_savedata("/payload.bin", payload_buffer, payload_size);
	if(write_ret) {
		printf("it failed.");
	} else {
		printf("stickerhax installed! special thanks: Gruetzig, smealum, yellows8");
	}

	// Main loop
	while (aptMainLoop())
	{
		gspWaitForVBlank();
		hidScanInput();

		u32 kDown = hidKeysDown();
		if (kDown & KEY_START)
			break; // break in order to return to hbmenu
	}

	romfsExit();
	gfxExit();
	return 0;
}
