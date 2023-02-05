// Shifr ©2020-3 Glebe A.N. structs
// Шифр ©2020-3 Глебов А.Н. структуры

# ifndef  SHIFR_STRUCT_H
# define  SHIFR_STRUCT_H

# include "type.h"
# include "number/struct.h"

# define  shifr_s_raspr_templ( V ) \
struct_raspr ( V ) { \
  uint8_t dice  [ shifr_deshi_size ( V ) - 1  ] ; \
  shifr_number_priv_type ( V ) pass  ; \
} ;

shifr_s_raspr_templ ( v2 )
shifr_s_raspr_templ ( v3 )

// 0x20 (space) ' '    ---     0x7e (tilde) '~'
// 0x20 (пробел) ' '    ---     0x7e (тильда) '~'
// 95 шт pcs
enum  { shifr_letters_count =
  ( ( UINT8_C ( '~' ) - UINT8_C ( ' ' ) ) + 1U )
} ;

// 0x30 '0' - 0x39 '9' , 0x41 'A' - 0x5a 'Z' , 0x61 'a' - 0x7a 'z'
// 62 шт pcs
enum  { shifr_letters_count2 =
  ( ( UINT8_C ( '9' ) - UINT8_C ( '0' ) ) + 1U +
    ( UINT8_C ( 'Z' ) - UINT8_C ( 'A' ) ) + 1U +
    ( UINT8_C ( 'z' ) - UINT8_C ( 'a' ) ) + 1U )
} ;

// 0x61 'a' - 0x7a 'z'
// 26 шт pcs
enum  { shifr_letters_count4 =
  ( ( UINT8_C ( 'z' ) - UINT8_C ( 'a' ) ) + 1U )
} ;

// 0x30 '0' - 0x39 '9'
// 10 шт pcs
enum  { shifr_letters_count_Digit =
  ( ( UINT8_C ( '9' ) - UINT8_C ( '0' ) ) + 1U )
} ;

# define  shifr_password_letters_size(  V ) shifr_password_letters_size_ ## V

enum  {
  shifr_password_letters_size ( v2 ) = 30 ,
  shifr_password_letters_size ( v3 ) = 180 ,
} ;

# include <stdio.h> //  FILE

struct  shifr_s_streambuf {  
  FILE  * file  ;
  uint8_t buf ;
  uint8_t bufbitsize  ;
} ;

# include <stdbool.h>
// убрать эхо в терминале
// close terminal echo
# include <termios.h>
# include <setjmp.h>

struct  s_ns_shifr  {
  // letters allowed in password :
  // буквы разрешённые в пароле :
  // ascii  
  char  letters [ shifr_letters_count ] ;  
  // a..zA..Z0..9
  char  letters2  [ shifr_letters_count2  ] ;
  // a..z
  char  letters4  [ shifr_letters_count4  ] ;
  // 0..9
  char  letters_Digit  [ shifr_letters_count_Digit  ] ;
  bool  localerus ; 

  // default state repository
  // хранилище дефолтного состояния
  struct termios stored_termios  ;

  // exceptions
  // исключения
  jmp_buf jump ;
  shifr_strcp string_exception ;

  union {
    // ver2
    shifr_t_raspr ( v2  ) raspr2 ;
    // ver3
    shifr_t_raspr ( v3  ) raspr3 ;
  } ;

  //  2 or 3
  //  2 или 3
  int use_version ; 
  
  // v2
  // secret code options for letters
  // варианты секретных кодов для буквы
  // 0 .. 3 - 0
  // 4 .. 7 - 1
  // 8 .. b - 2
  // c .. f - 3

  // v3
  // secret code options for letters
  // варианты секретных кодов для буквы
  // 0 .. 7 -  0
  // 8 .. f -  1
  // 10 .. 17 -  2
  // 18 .. 1f -  3
  // 20 .. 27 -  4
  // 28 .. 2f -  5
  // 30 .. 37 -  6
  // 38 .. 3f -  7

  bool  flagtext  ;

  union {
    uint8_t volatile  shifrv2 [ shifr_deshi_size ( v2 ) ] ;
    uint8_t volatile  shifrv3 [ shifr_deshi_size ( v3 ) ] ;
  } ;
  
  union {
    uint8_t volatile  deshiv2 [ shifr_deshi_size ( v2 ) ] ;
    uint8_t volatile  deshiv3 [ shifr_deshi_size ( v3 ) ] ;
  } ;
  
  // 62 or 95 or 26 or 10
  // алфавит пароля 62 или 95 или 26 или 10
  int password_alphabet ; 
  
  union {
    // ver2
    char  volatile  password_letters2 [ shifr_password_letters_size ( v2 ) ] ;
    // ver3
    char  volatile  password_letters3 [ shifr_password_letters_size ( v3 ) ] ;
  } ;
    
// private :
  shifr_t_streambuf filebuffrom ;
  shifr_t_streambuf filebufto ;
  // для : write6 , writeflushzero в текстовом режиме
  // for : write6 , writeflushzero in text mode
  int bytecountw  ; 
  uint8_t old_last_data ;
  uint8_t old_last_salt ;
  // text mode remember string place
  int charcount ;
  // stream buffer ver 2 for decrypt text mode
  // буфер потока вер 2 для расшифровки текстового режима
  char  buf2  [ 3 ] ;
  uint8_t buf2index ;
  // ver3
  int bitscount ;
  uint8_t secretdata  [ 4 ] ;
  uint8_t secretdatasalt  [ 3 ] ;
} ;

struct  shifr_s_arrcps  {
  shifr_arrcp cp  ;
  size_t  s ;
} ;

struct  shifr_s_arrps {
  shifr_arrp  p ;
  size_t  s ;
} ;

struct  shifr_s_size_io {
  size_t  i ;
  size_t  o ;
} ;

# endif // SHIFR_STRUCT_H
