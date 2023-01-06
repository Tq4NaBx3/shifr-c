// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# ifndef  SHIFR_PRIVATE_H
# define  SHIFR_PRIVATE_H

# include <stdbool.h>
# include "type.h"
# include "template.h"

// generate random number [ fr .. to ]
unsigned  int shifr_uirandfrto  ( t_ns_shifr * ns_shifrp ,
  unsigned  int fr , unsigned  int to ) ;

// data_size = 4
void shifr_datasalt2 ( t_ns_shifr * ns_shifrp ,
  shifr_arrcp secretdata , shifr_arrp secretdatasalt ,
  size_t data_size ) ;
  
// data_size = 1 .. 3
void shifr_datasalt3 ( t_ns_shifr * ns_shifrp ,
  shifr_arrcp secretdata , shifr_arrp secretdatasalt ,
  size_t data_size ) ;

// пишу по шесть бит
// secretdatasaltsize - количество шести-битных отделов (2 или 3)
// encrypteddata - массив шести-битных чисел
// I write in six bits
// secretdatasaltsize - the number of six-bit divisions (2 or 3)
// encrypteddata - array of six-bit numbers
void  shifr_streambuf_write3 ( t_ns_shifr * ns_shifrp ,
  shifr_t_streambuf * me  , uint8_t const (  * encrypteddata ) [ 3 ] ,
  uint8_t secretdatasaltsize , bool flagtext ,
  uint8_t * restrict * output_bufferp , size_t * writesp ,
  size_t  outputs ) ;

// версия 3 пишу три бита для расшифровки
// version 3 write three bits to decode
void  shifr_streambuf_write3bits ( t_ns_shifr * ns_shifrp ,
  uint8_t encrypteddata , uint8_t * restrict * output_bufferp ,
  size_t * writesp )  ;

// ! to remove , make random 0..16!-1
// generate array raspr2.dice
// inits array [ 0..15 , 0..14 , ... , 0..2 , 0..1 ]
void  shifr_generate_dices2 ( t_ns_shifr * ) ;

// ! to remove , make random 0..64!-1
// generate array raspr3.dice
// inits array [ 0..63 , 0..62 , ... , 0..2 , 0..1 ]
void  shifr_generate_dices3 ( t_ns_shifr * ) ;

// ! to remove , make random 0..16!-1
// convert raspr2.dice as array to big number raspr2.pass
//  + create tables shifr deshi
// [ 0..15 , 0..14 , 0..13 , ... , 0..2 , 0..1 ] =
// [ x , y , z , ... , u , v ] =
// = x + y * 16 + z * 16 * 15 + ... + u * 16! / 2 / 3 + v * 16! / 2 = 
// 0 .. 16!-1
void  shifr_dices_to_number2 ( t_ns_shifr * ) ;

// ! to remove , make random 0..64!-1
// convert raspr3.dice as array to big number raspr3.pass
//  + create tables shifr deshi
// [ 0..63 , 0..62 , 0..61 , ... , 0..2 , 0..1 ] = 
// [ x , y , z , ... , u , v ] =
// = x + y * 64 + z * 64 * 63 + ... + u * 64! / 2 / 3 + v * 64! / 2 = 
// 0 .. 64!-1
void  shifr_dices_to_number3 ( t_ns_shifr * ) ;

/*
Encryption
Reads data from 'input.cp' of size 'input.s' bytes,
writes to 'output.p' of size 'output.s' bytes,
returns the size of read and written data
Шифрование
Читает данные из 'input.cp' размера 'input.s' байт ,
записывает в 'output.p' размера 'output.s' байт ,
возвращает размер считаных и записаных данных
*/
shifr_size_io shifr_encrypt2  ( t_ns_shifr * , shifr_arrcps input ,
  shifr_arrps output )  ;
shifr_size_io shifr_encrypt3  ( t_ns_shifr * , shifr_arrcps input ,
  shifr_arrps output )  ;

/*
Finished buffer encryption, returns output_buffer size written
Заканчивает шифрование буфера, возвращает размер записаных данных.
*/
uint8_t shifr_encrypt2_flush  ( t_ns_shifr * , shifr_arrps output )  ;

/*
Decryption
Reads data from 'input.cp' of size 'input.s' bytes,
writes to 'output.p' of size 'output.s' bytes,
returns the size of read and written data
Расшифровка
Читает данные из 'input.cp' размера 'input.s' байт ,
записывает в 'output.p' размера 'output.s' байт ,
возвращает размер считаных и записаных данных
*/
shifr_size_io  shifr_decrypt2 ( t_ns_shifr * , shifr_arrcps input ,
  shifr_arrps output ) ;
  
/*
Decryption
Расшифровка
*/
shifr_size_io  shifr_decrypt3 ( t_ns_shifr * , shifr_arrcps input ,
  shifr_arrps output ) ;

uint8_t  shifr_streambuf_writeflushzero3 ( t_ns_shifr * , shifr_arrps ) ;

enum  { shifr_memsetv_default_byte  = 0x55  } ;

void volatile * shifr_memsetv ( void volatile * str , uint8_t ch , size_t n ) ;

// Console recovery of default state
// Восстановление дефолтного состояния консоли
void shifr_reset_keypress ( t_ns_shifr * ) ;

// Disable ping and input buffering
// Отключить эхо-вывод и буферизацию ввода
void shifr_set_keypress ( t_ns_shifr * ) ;

shifr_password_to_string_templ_dec  ( v2 )
shifr_password_to_string_templ_dec  ( v3 )  

shifr_string_to_password_templ_dec  ( v2 )
shifr_string_to_password_templ_dec  ( v3 )

shifr_number_dec_mul_byte ( v2 )
shifr_number_dec_mul_byte ( v3 )

shifr_number_dec_set0 ( v2 )
shifr_number_dec_set0 ( v3 )

/*
 Translation of big number 'raspr.pass' 
to the encryption table 'shifr', decryption 'deshi'
 Перевод большого числа 'raspr.pass' в таблицы шифрования 'shifr' ,
дешифровки 'deshi'
*/
void  shifr_password_load_uni ( t_ns_shifr * ) ;
void  shifr_password_from_dice_uni ( t_ns_shifr * ) ;

# endif // SHIFR_PRIVATE_H
