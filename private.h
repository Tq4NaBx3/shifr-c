// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# include <stdbool.h>
# include "type.h"

// generate random number [ fr .. to ]
unsigned  int shifr_uirandfrto  ( t_ns_shifr * const ns_shifrp ,
  unsigned  int const fr , unsigned  int const to ) ;

// data_size = 4
void shifr_datasole2 ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcp const secretdata , shifr_arrp const secretdatasole ,
  size_t const data_size )  ;
  
// data_size = 1 .. 3
void shifr_datasole3 ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcp const secretdata , shifr_arrp const secretdatasole ,
  size_t const data_size )  ;

// пишу по шесть бит
// secretdatasolesize - количество шести-битных отделов (2 или 3)
// encrypteddata - массив шести-битных чисел
// I write in six bits
// secretdatasolesize - the number of six-bit divisions (2 or 3)
// encrypteddata - array of six-bit numbers
void  shifr_streambuf_write3 ( t_ns_shifr * const ns_shifrp ,
  shifr_t_streambuf * const me  , uint8_t const (  * const encrypteddata ) [ 3 ] ,
  uint8_t const secretdatasolesize , bool const  flagtext ,
  uint8_t * restrict * const output_bufferp , size_t * const writesp ,
  size_t  const outputs ) ;

// версия 3 пишу три бита для расшифровки
// version 3 write three bits to decode
void  shifr_streambuf_write3bits ( t_ns_shifr * const ns_shifrp ,
  uint8_t const encrypteddata , uint8_t * restrict * const output_bufferp ,
  size_t * const writesp )  ;
