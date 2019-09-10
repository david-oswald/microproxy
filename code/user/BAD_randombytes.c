#include "osapi.h"
#include "c_types.h"
void randombytes(unsigned char *ptr, unsigned long long length)
{
	os_printf("\n\nrandombytes called!!!\n\n");
	//int i;
	u32 t = system_get_time();
	if (length <= 32) {
		os_memcpy(ptr, &t, length);
	} else {
		while (length > 32) {
			os_memcpy(ptr, &t, 32);
			//i+=32;
			ptr = &ptr[32];
			length -= 32;
			t = system_get_time();
		}
		t = system_get_time();
		os_memcpy(ptr, &t, length);
	}

	/*int i;
	 * for ( i = 0; i < length; i++) {
	 * ptr = i;
	 * ptr ++;
	 * }
	 */
}
