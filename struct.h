# include "type.h"

# define  shifr_number_def( N ) \
  struct  shifr_s_number ## N { \
    /* array */ \
    uint8_t HRDG [ N ] ; \
  } ;

# define  number_def  shifr_number_def

number_def  ( number_size2 )

struct  s_raspr4 {
  uint8_t dice  [ deshi_size2 - 1  ] ;
  number_type ( number_size2 ) pass  ;
  } ;

number_def  ( number_size3 )

struct  s_raspr6 {
  uint8_t dice  [ deshi_size6 - 1 ] ;
  number_type ( number_size3 ) pass  ;
  } ;

// 0x20 (space) ' '    ---     0x7e (tilde) '~'
// 0x20 (пробел) ' '    ---     0x7e (тильда) '~'
// 95 шт pcs
# define letters_count (UINT8_C(('~' - ' ') + 1))

// 0x30 '0' - 0x39 '9' , 0x41 'A' - 0x5a 'Z' , 0x61 'a' - 0x7a 'z'
// 62 шт pcs
# define letters_count2 (UINT8_C( \
  ('9' - '0') + 1 + ('Z' - 'A') + 1 + ('z' - 'a') + 1 ))

struct  s_streambuf  {
  // file
  FILE  * oRmq  ;
  // buf
  uint8_t FmoX ;
  // bufbitsize
  uint8_t XUvM  ;
  // для : write6 , writeflushzero в текстовом режиме
  // for : write6 , writeflushzero in text mode
  // bytecount
  int D6h7 ; 
  } ;

# include <setjmp.h>
// убрать эхо в терминале
// close terminal echo
# include <termios.h>
# include <stdbool.h>
  
struct  s_ns_shifr  {
  // letters allowed in password :
  // буквы разрешённые в пароле :
  // ascii  
  char  letters [ letters_count ] ;  
  // a..zA..Z0..9
  char  letters2 [ letters_count2 ] ;    
  bool  localerus ; 

  // default state repository
  // хранилище дефолтного состояния
  struct termios stored_termios  ;

  // exceptions
  // исключения
  jmp_buf jump ;
  strcp string_exception ;

  // ver2
  t_raspr4 raspr4 ;
  // ver3
  t_raspr6 raspr6 ;

  //  2 or 3
  //  2 или 3
  int use_version ; 

  FILE  * filefrom  ;
  FILE  * fileto  ;
  bool  flagtext  ;

  uint8_t shifr [ deshi_size2 ] ;
  uint8_t shifr6 [ deshi_size6 ] ;
  // secret code options for letters
  // варианты секретных кодов для буквы
  // 0 .. 3 - 0
  // 4 .. 7 - 1
  // 8 .. b - 2
  // c .. f - 3
  uint8_t deshi [ deshi_size2 ] ;
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
  uint8_t deshi6 [ deshi_size6 ] ;
  // 62 or 95 
  // алфавит пароля 62 или 95
  int password_alphabet ; 
  // ver2
  char  password_letters2 [ 20  ] ;
  // ver3
  char  password_letters3 [ 100 ] ;
// private :
  t_streambuf filebuffrom ;
  t_streambuf filebufto ;
  uint8_t old_last_data ;
  uint8_t old_last_sole ;
  // text mode remember string place
  int charcount ;
  // stream buffer ver 2 for decrypt text mode
  // буфер потока вер 2 для расшифровки текстового режима
  char  buf3  [ 3 ] ;
  uint8_t buf3index ;
  // ver3
  int bitscount ;
  uint8_t secretdata  [ 4 ] ;
  uint8_t secretdatasole  [ 3 ] ;
  } ;

struct  s_arrcps {
  arrcp cp  ;
  size_t  s ;
} ;

struct  s_arrps {
  arrp  p ;
  size_t  s ;
} ;

struct  s_size_io  {
  size_t  i ;
  size_t  o ;
} ;
