// Shifr ©2020-3 Glebe A.N. private
// Шифр ©2020-3 Глебов А.Н. приватн

# ifndef  SHIFR_PRIVATE_H
# define  SHIFR_PRIVATE_H

// generate secret random number [ fr .. to ]
struct  s_shifr_fr_to {
  t_ns_shifr  * volatile  sh  ;
  unsigned  int volatile  fr  ;
  unsigned  int volatile  to  ;
  unsigned  int volatile  res ;
} ;
void  shifr_uirandfrto  ( struct  s_shifr_fr_to volatile  * ) ;

# define  shifr_datasalt( N ) shifr_datasalt_  ##  N

# define  shifr_datasalt_dec( N ) \
void  shifr_datasalt ( N ) ( t_ns_shifr * ns_shifrp , \
  shifr_arrcp secretdata , shifr_arrp secretdatasalt , size_t data_size ) ;
  
// data_size = 4
shifr_datasalt_dec ( v2 )
// data_size = 1 .. 3
shifr_datasalt_dec ( v3 )

// пишу по шесть бит
// secretdatasaltsize - количество шести-битных отделов (2 или 3)
// encrypteddata - массив шести-битных чисел
// I write in six bits
// secretdatasaltsize - the number of six-bit divisions (2 or 3)
// encrypteddata - array of six-bit numbers

typedef struct  s_shifr_streambuf_write3  t_shifr_streambuf_write3  ;

struct  s_shifr_streambuf_write3  {
  uint8_t const (  * const encrypteddata ) [ 3 ] ;
  t_ns_shifr * const ns_shifrp ;
  uint8_t * restrict * const output_bufferp ;
  size_t * const writesp ;
  size_t  const outputs ;
  uint8_t const secretdatasaltsize ;
} ;

void  shifr_streambuf_write3 ( t_shifr_streambuf_write3 ) ;

// версия 3 пишу три бита для расшифровки
// version 3 write three bits to decode
void  shifr_streambuf_write3bits ( t_ns_shifr * ns_shifrp ,
  uint8_t encrypteddata , uint8_t * restrict * output_bufferp ,
  size_t * writesp )  ;

# define  shifr_generate_dices( N ) shifr_generate_dices_  ##  N

# define  shifr_generate_dices_dec( N ) \
void  shifr_generate_dices ( N ) ( t_ns_shifr * ) ;
  
// ! to remove , make random 0..16!-1
// generate array raspr2.dice
// inits array [ 0..15 , 0..14 , ... , 0..2 , 0..1 ]
shifr_generate_dices_dec ( v2 )

// ! to remove , make random 0..64!-1
// generate array raspr3.dice
// inits array [ 0..63 , 0..62 , ... , 0..2 , 0..1 ]
shifr_generate_dices_dec ( v3 )

# define  shifr_dices_to_number( N ) shifr_dices_to_number_  ##  N

# define  shifr_dices_to_number_dec( N ) \
void  shifr_dices_to_number ( N ) ( t_ns_shifr * ) ;

// ! to remove , make random 0..16!-1
// convert raspr2.dice as array to big number raspr2.pass
//  + create tables shifr deshi
// [ 0..15 , 0..14 , 0..13 , ... , 0..2 , 0..1 ] =
// [ x , y , z , ... , u , v ] =
// = x + y * 16 + z * 16 * 15 + ... + u * 16! / 2 / 3 + v * 16! / 2 = 
// 0 .. 16!-1
shifr_dices_to_number_dec ( v2 )

// ! to remove , make random 0..64!-1
// convert raspr3.dice as array to big number raspr3.pass
//  + create tables shifr deshi
// [ 0..63 , 0..62 , 0..61 , ... , 0..2 , 0..1 ] = 
// [ x , y , z , ... , u , v ] =
// = x + y * 64 + z * 64 * 63 + ... + u * 64! / 2 / 3 + v * 64! / 2 = 
// 0 .. 64!-1
shifr_dices_to_number_dec ( v3 )

/*
Finished buffer encryption, returns output_buffer size written
Заканчивает шифрование буфера, возвращает размер записаных данных.
*/
uint8_t shifr_encrypt2_flush  ( t_ns_shifr * , shifr_arrps output )  ;

uint8_t  shifr_streambuf_writeflushzero3 ( t_ns_shifr * , shifr_arrps ) ;

enum  { shifr_memsetv_default_byte  = 0x55  } ;

void volatile * shifr_memsetv ( void volatile * str , uint8_t ch , size_t n ) ;

// Console recovery of default state
// Восстановление дефолтного состояния консоли
void shifr_reset_keypress ( t_ns_shifr * ) ;

// Disable ping and input buffering
// Отключить эхо-вывод и буферизацию ввода
void shifr_set_keypress ( t_ns_shifr * ) ;

# define  shifr_password_to_string_templ( N ) \
  shifr_password  ##  N ##  _to_string_templ

# define  shifr_password_to_string_templ_dec( N ) \
void  shifr_password_to_string_templ  ( N ) ( \
  shifr_number_type ( N ) const * password0 , shifr_strvp string ,  \
  shifr_strp letters , uint8_t letterscount  ) ;
  
shifr_password_to_string_templ_dec  ( v2 )
shifr_password_to_string_templ_dec  ( v3 )  

# define  shifr_string_to_password_templ( N ) \
  shifr_string_to_password  ##  N ##  _templ

# define  shifr_string_to_password_templ_dec( N ) \
void  shifr_string_to_password_templ  ( N ) ( t_ns_shifr * , \
  shifr_strvcp  string , shifr_number_type ( N ) * password , \
  shifr_strcp letters , uint8_t letterscount  ) ;

shifr_string_to_password_templ_dec  ( v2 )
shifr_string_to_password_templ_dec  ( v3 )

/*
 Translation of big number 'raspr.pass' 
to the encryption table 'shifr', decryption 'deshi'
 Перевод большого числа 'raspr.pass' в таблицы шифрования 'shifr' ,
дешифровки 'deshi'
*/
void  shifr_password_load_uni ( t_ns_shifr * ) ;
void  shifr_password_from_dice_uni ( t_ns_shifr * ) ;

# ifdef  SHIFR_DEBUG
uint8_t shifr_letter_to_bits6 ( t_ns_shifr * , char  letter  ) ;
char  shifr_bits6_to_letter ( t_ns_shifr * , uint8_t bits6 ) ;
# else
inline  uint8_t shifr_letter_to_bits6 ( char  letter  ) ;
inline  char  shifr_bits6_to_letter ( uint8_t bits6 ) ;
# endif

void  shifr_data_xor3  ( uint8_t * old_last_data , uint8_t * old_last_salt ,
  shifr_arrp  secretdatasalt  , size_t  data_size ) ;

void  shifr_crypt_decrypt ( shifr_arrp  datap ,
  shifr_arrvcp  tablep  , shifr_arrp  encrp , size_t  data_size ) ;
  
void  shifr_data_xor2 ( t_ns_shifr  * ns_shifrp ,
  shifr_arrp  secretdatasalt  , size_t  data_size ) ;

# define  shifr_decrypt_salt( N ) shifr_decrypt_salt_ ## N

# define  shifr_decrypt_salt_dec( N ) \
void  shifr_decrypt_salt ( N ) ( shifr_arrp  datap , \
  shifr_arrvcp  tablep  , shifr_arrp  decrp , size_t  data_size , \
  uint8_t * old_last_salt , uint8_t * old_last_data ) ;
  
shifr_decrypt_salt_dec  ( v2  )
shifr_decrypt_salt_dec  ( v3  )

inline  void  shifr_initarr ( shifr_arrvp p ,
  uint8_t codefree  , size_t  loc_shifr_deshi_size  ) ;

// читаю 6 бит
// 6 bits reads

// ! to do : arguments as struct

bool  isEOBstreambuf_read6bits ( t_ns_shifr * const ns_shifrp ,
  uint8_t * const encrypteddata , size_t * const  readsp ,
  uint8_t const * restrict * const input_bufferp , size_t const inputs ) ;

# define  shifr_enter_password_name( vv  ) shifr_enter_password_  ## vv
// from stdin get password string -> make big number
void  shifr_enter_password_name ( v2 ) ( t_ns_shifr * )  ;
void  shifr_enter_password_name ( v3 ) ( t_ns_shifr * )  ;

extern  char  const shifr_base64_num_to_let [ 0x40  ] ;

extern  unsigned  int const shifr_base64_let_to_num [ ] ;

# endif // SHIFR_PRIVATE_H
