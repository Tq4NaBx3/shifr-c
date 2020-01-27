// Шифр ©2020 Глебов А.Н.
// Shifr ©2020 Glebe A.N.

# include <stdio.h>
# include <stdlib.h>
# include <errno.h>

# include "shifr.h"

# undef shifr_number_array
# define  shifr_number_array  shifr_number_array_pub
number_def_set0 ( 6 )
number_def_mul_byte ( 6 )
number_def_set0 ( 37 )
number_def_mul_byte ( 37 )
# undef shifr_number_array
# define  shifr_number_array  shifr_number_array_pri
  
# ifdef SHIFR_DEBUG
void  printarr  ( strcp const  name , arrcp const p ,
  size_t const arrsize , FILE * const f ) {
  fprintf  ( f  , u8"%s = [ " , * name  ) ;
  uint8_t const * i = & ( ( * p ) [ 0 ] ) ;
  do {
    fprintf  ( f  , "%x , " , ( int ) ( * i ) ) ; 
    ++  i ;
  } while ( i not_eq  & ( ( * p ) [ arrsize ] ) ) ;
  fputs ( u8"]\n" , f ) ; }
# endif

# define  crypt_decrypt shifr_crypt_decrypt
static inline void  crypt_decrypt ( arrp const datap , arrcp const tablep ,
  arrp const encrp , size_t const data_size ) {
  uint8_t const * id = & ( ( * datap ) [ data_size ] ) ;
  uint8_t * ied = & ( ( * encrp ) [ data_size ] ) ;
  do {
    -- id ;
    --  ied ;
    ( * ied ) = ( * tablep ) [ * id ] ;
  } while ( id not_eq & ( ( * datap ) [ 0 ] ) ) ; }
  
# define  decrypt_sole  shifr_decrypt_sole
static inline void  decrypt_sole ( arrp const datap , arrcp const tablep ,
  arrp const decrp , size_t const data_size ,
  uint8_t * const restrict old_last_sole ,
  uint8_t * const restrict old_last_data ) {
  uint8_t const * restrict  id = & ( ( * datap ) [ 0 ] ) ;
  uint8_t * restrict  ide = & ( ( * decrp ) [ 0 ] ) ;
  do {
    { uint8_t const data_sole = ( * tablep ) [ * id ] ;
      ( * ide ) = ( data_sole >>  2 ) xor ( * old_last_sole ) ;
      ( * old_last_sole ) = (  data_sole bitand  0x3 ) xor ( * old_last_data ) ;
      ( * old_last_data ) = ( * ide ) ; }
    ++  id  ;
    ++  ide ;
  } while ( id not_eq & ( ( * datap ) [ data_size ] ) ) ; }

# define  decrypt_sole6  shifr_decrypt_sole6
static inline void  decrypt_sole6 ( arrp const datap , arrcp const tablep ,
  arrp const decrp , size_t const data_size ,
  uint8_t * const restrict old_last_sole ,
  uint8_t * const restrict old_last_data ) {
  uint8_t const * restrict  id = & ( ( * datap ) [ 0 ] ) ;
  uint8_t * restrict  ide = & ( ( * decrp ) [ 0 ] ) ;
  do {
    { uint8_t const data_sole = ( * tablep ) [ * id ] ;
      ( * ide ) = ( data_sole >>  3 ) xor ( * old_last_sole ) ;
      ( * old_last_sole ) = (  data_sole bitand  0x7 ) xor ( * old_last_data ) ;
      ( * old_last_data ) = ( * ide ) ; }
    ++  id  ;
    ++  ide ;
  } while ( id not_eq & ( ( * datap ) [ data_size ] ) ) ; }

t_ns_shifr  ns_shifr = {
  . use_version  = 6 ,
  . flagtext = false ,
  . shifr = { } ,
  . deshi = { } ,
  . shifr6 = { } ,
  . deshi6 = { } ,
  . password_alphabet = 62 ,
} ;
    
# define  shifr_password_to_string_templ_def( N ) \
void  shifr_password##N##_to_string_templ ( \
  number_type ( N ) const * const restrict password0 , strp const string ,  \
  strp letters , uint8_t const letterscount  ) {  \
  char * stringi = & ( ( * string )  [ 0 ] ) ;  \
  if ( number_not_zero  ( N ) ( password0 ) ) { \
    number_type ( N ) password = * password0  ; \
    do {  \
      /* здесь предыдущие размеры заняли место паролей */ \
      number_dec ( N ) ( & password  ) ;  \
      ( * stringi ) = ( * letters ) [ number_div_mod ( N ) ( & password , \
        letterscount ) ] ;  \
      ++  stringi ; \
    } while ( number_not_zero ( N ) ( & password ) ) ; }  \
  ( * stringi ) = '\00' ;  }
# define  password_to_string_templ_def  shifr_password_to_string_templ_def
password_to_string_templ_def  ( 6 )
password_to_string_templ_def  ( 37 )

# define  shifr_string_to_password_templ_def( N ) \
void  shifr_string_to_password##N##_templ ( strcp const string , \
  number_type ( N ) * const restrict password ,  \
  strcp const letters , uint8_t const letterscount  ) { \
  char const * restrict stringi = & ( ( * string )  [ 0 ] ) ; \
  if  ( ( * stringi ) == '\00' ) { \
    number_set0 ( N ) ( password  ) ; \
    return ; } \
  number_type ( N ) pass ; \
  number_set0 ( N ) ( & pass  ) ; \
  number_type ( N ) mult ;  \
  number_set_byte ( N ) ( & mult , 1 ) ;  \
  do  { \
    uint8_t i = letterscount ;  \
    do {  \
      -- i ;  \
      if ( ( * stringi ) == ( * letters ) [ i ] ) goto found ; \
    } while ( i ) ; \
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?  \
      ( strcp ) & u8"неправильная буква в пароле" : \
      ( strcp ) & "wrong letter in password" ) ;  \
    longjmp ( ns_shifr  . jump  , 1 ) ; \
found : ; \
    { number_type ( N ) tmp = mult ;  \
      number_mul_byte ( N ) ( & tmp , i + 1 ) ; \
      number_add ( N ) ( &  pass  , & tmp )  ; }  \
    number_mul_byte ( N ) ( & mult , letterscount ) ; \
    ++  stringi ; \
  } while ( ( * stringi ) not_eq '\00' ) ;  \
  ( * password  ) = pass ; }
# define  string_to_password_templ_def  shifr_string_to_password_templ_def
string_to_password_templ_def  ( 6 )
string_to_password_templ_def  ( 37 )

static inline void datasole ( arrcp const secretdata , arrp const secretdatasole ,
  size_t const data_size ) {
  uint8_t const * restrict  id = &  ( ( * secretdata  ) [ data_size ] ) ;
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ data_size ] ) ;
  int ran = rand ( )  ;
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 10 =>
    //   10_00 или 10_01 или 10_10 или 10_11
    // в таблице всё рядом, 4 варианта равномерно распределены
    ( * ids ) = ( ( * id  ) <<  2 ) bitor ( ran bitand  0x3 ) ;
    ran >>= 2 ;
  } while ( id not_eq & ( ( * secretdata  ) [ 0 ] ) ) ; }

static void datasole6 ( arrcp const secretdata , arrp const secretdatasole ,
  size_t const data_size ) {
  uint8_t const * restrict  id = &  ( ( * secretdata  ) [ data_size ] ) ;
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ data_size ] ) ;
  int ran = rand ( )  ;
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 101 =>
    //   101_000 или 101_001 или ... или 101_111
    // в таблице всё рядом, 8 вариантов равномерно распределены
    ( * ids ) = ( ( * id  ) <<  3 ) bitor ( ran bitand  0x7 ) ;
    ran >>= 3 ;
  } while ( id not_eq & ( ( * secretdata  ) [ 0 ] ) ) ; }

static inline void  data_xor  ( uint8_t * const restrict  old_last_data ,
  uint8_t * const restrict  old_last_sole ,
  arrp  const secretdatasole  , size_t  const data_size ) {
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ 0 ] ) ;
  do {
    uint8_t const cur_data = ( * ids ) >> 2 ;
    uint8_t const cur_sole = ( * ids ) bitand 0x3 ;
    // главное данные , хвост - соль : 01 =>
    //   01_00 или 01_01 или 01_10 или 01_11
    // в таблице всё рядом, 4 варианта равномерно распределены
    // данные сыпью предыдущей солью
    ( * ids ) xor_eq  ( ( * old_last_sole ) << 2  ) ;
    ( * ids ) xor_eq  ( * old_last_data ) ;
    // берю свежую соль
    ( * old_last_sole ) = cur_sole ;
    ( * old_last_data ) = cur_data ;
    ++  ids ;
  } while ( ids not_eq & ( ( * secretdatasole ) [ data_size ] ) ) ; }

static inline void  data_xor6  ( uint8_t * const restrict  old_last_data ,
  uint8_t * const restrict  old_last_sole ,
  arrp  const secretdatasole  , size_t  const data_size ) {
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ 0 ] ) ;
  do {
    uint8_t const cur_data = ( * ids ) >> 3 ;
    uint8_t const cur_sole = ( * ids ) bitand 0x7 ;
    // главное данные , хвост - соль : 101 =>
    //   101_000 или 101_001 или ... или 101_111
    // в таблице всё рядом, 8 вариантов равномерно распределены
    // данные сыпью предыдущей солью
    ( * ids ) xor_eq  ( ( * old_last_sole ) << 3  ) ;
    ( * ids ) xor_eq  ( * old_last_data ) ;
    // берю свежую соль
    ( * old_last_sole ) = cur_sole ;
    ( * old_last_data ) = cur_data ;
    ++  ids ;
  } while ( ids not_eq & ( ( * secretdatasole ) [ data_size ] ) ) ; }

// ';' = 59 ... 'z' = 122 , 122 - 59 + 1 == 64
static  inline  char  bits6_to_letter ( uint8_t const bits6 ) {
  return  ';'  + bits6  ; }

static  inline  uint8_t letter_to_bits6 ( char  const letter  ) {
  return  letter  - ';' ; }
    
// Отключить эхо-вывод и буферизацию ввода
void set_keypress (void) {
  if  ( tcgetattr ( 0 , & ns_shifr  . stored_termios  ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifr . localerus ?
      u8"ошибка чтения tcgetattr : %s\n" :
      "error read tcgetattr : %s\n" ) ,se ) ;
    ns_shifr  . string_exception  = ( strcp ) se ;
    longjmp(ns_shifr  . jump,1); }

  struct termios new_termios = ns_shifr . stored_termios  ;
  new_termios.c_lflag  and_eq ~(ECHO bitor ICANON);
  new_termios.c_cc[VMIN] = 1;  
  new_termios.c_cc[VTIME] = 0; 
 
  if(tcsetattr(0, TCSANOW, & new_termios)){
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifr . localerus ?
      u8"ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifr  . string_exception  = ( strcp ) se ;
    longjmp(ns_shifr  . jump,1); } }
 
// Восстановление дефолтного состояния
void reset_keypress ( void  ) {
  if  ( tcsetattr ( 0 , TCSANOW , & ns_shifr . stored_termios ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifr . localerus ?
      u8"ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifr  . string_exception  = ( strcp ) se ;
    longjmp(ns_shifr  . jump,1); } }

# undef streambuf_file
# define  streambuf_file  streambuf_file_pub
# undef streambuf_buf
# define  streambuf_buf  streambuf_buf_pub
# undef streambuf_bufbitsize
# define  streambuf_bufbitsize  streambuf_bufbitsize_pub
# undef streambuf_bytecount
# define  streambuf_bytecount  streambuf_bytecount_pub

static  inline  int streambuf_ByteCount  ( t_streambuf const * const restrict me ) {
  return  streambuf_bytecount ( me  ) ; }

static  inline  uint8_t streambuf_BufBitSize  (
  t_streambuf const * const restrict me ) {
  return  streambuf_bufbitsize ( me  ) ; }

static  inline  uint8_t streambuf_Buf (
  t_streambuf const * const restrict me ) {
  return  streambuf_buf ( me  ) ; }
  
// читаю 6 бит
// 6 bits reads
static inline bool  isEOFstreambuf_read6bits ( t_streambuf * const restrict me  ,
  uint8_t * const encrypteddata ) {
  if  ( ( not ( ns_shifr  . flagtext ) ) and streambuf_bufbitsize  ( me  ) >= 6 ) {
    streambuf_bufbitsize  ( me  ) -=  6 ;
    ( * encrypteddata ) = streambuf_buf ( me  ) bitand ( 0x40 - 1 ) ;
    streambuf_buf ( me  ) >>= 6 ;
    return  false ; }
  uint8_t buf ;
  { size_t  const nreads  = fread ( & buf , 1 , 1 , streambuf_file  ( me  ) ) ;
    if ( nreads ==  0 ) {
      if  ( feof  ( streambuf_file  ( me  ) ) ) return  true  ;
      if  ( ferror  ( streambuf_file  ( me  ) ) ) {
        clearerr ( streambuf_file  ( me  ) ) ;
        ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
          ( strcp ) &
          u8"isEOFstreambuf_read6bits: ошибка чтения шести бит" :
          ( strcp ) & "isEOFstreambuf_read6bits: six bits read error" ) ;
        longjmp(ns_shifr  . jump,1); } } } // nreads
  if  ( ns_shifr  . flagtext  ) {
    // читаем одну букву ';'-'z' -> декодируем в шесть бит
    // reads one letter ';'-'z' -> decode to six bits
    while ( ( buf < ((uint8_t)';') ) or ( buf > ((uint8_t)'z') ) ) {
      { size_t  const nreads  = fread ( & buf , 1 , 1 , streambuf_file  ( me  ) ) ;
        if ( nreads ==  0 ) {
          if  ( feof  ( streambuf_file  ( me  ) ) ) return  true  ;
          if  ( ferror  ( streambuf_file  ( me  ) ) ) {
            clearerr ( streambuf_file  ( me  ) ) ;
            ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
              ( strcp ) &
              u8"isEOFstreambuf_read6bits: ошибка чтения шести бит из текста" :
              ( strcp ) &
              "isEOFstreambuf_read6bits: six bits read error from text" ) ;
            longjmp(ns_shifr  . jump,1); } } } // nreads
          }
    ( * encrypteddata ) = letter_to_bits6 ( buf ) ; }
  else  {
    ( * encrypteddata ) = ( streambuf_buf ( me  ) bitor 
      ( buf <<  streambuf_bufbitsize  ( me  ) ) ) bitand ( 0x40 - 1 )  ;
    streambuf_buf ( me  ) = buf >>  ( 6 - streambuf_bufbitsize  ( me  ) ) ;
    streambuf_bufbitsize  ( me  ) +=  2 ; } // + 8 - 6
  return  false ; }
        
// пишу по шесть бит
// secretdatasolesize - количество шести-битных отделов (2 или 3)
// encrypteddata - массив шести-битных чисел
// I write in six bits
// secretdatasolesize - the number of six-bit divisions (2 or 3)
// encrypteddata - array of six-bit numbers
static void  streambuf_write6 ( t_streambuf * const restrict me  ,
  uint8_t const (  * const encrypteddata ) [ 3 ] ,
  uint8_t const secretdatasolesize , bool const  flagtext ) {
  if  ( flagtext  ) {
    for ( uint8_t i = 0 ; i < secretdatasolesize ; ++  i ) {
      char  buf2  = bits6_to_letter ( ( * encrypteddata ) [ i ] ) ;
        size_t  writen_count  ;
        writen_count  = fwrite  ( & buf2  , 1 , 1 , streambuf_file  ( me  ) ) ;
        if  ( writen_count  ==  0 ) {
          clearerr  ( streambuf_file  ( me  ) ) ; 
          ns_shifr  . string_exception  = ( ns_shifr  . localerus ? 
            ( strcp ) & u8"streambuf_write6: ошибка записи байта"  :
            ( strcp ) & "streambuf_write6: byte write error" ) ;
          longjmp ( ns_shifr  . jump  , 1 ) ; }
        ++  streambuf_bytecount ( me  ) ;
        if  ( streambuf_bytecount ( me  ) >=  60  ) {
          streambuf_bytecount ( me  ) = 0 ;
          buf2  = '\n'  ;
          writen_count  = fwrite  ( & buf2  , 1 , 1 ,
            streambuf_file  ( me  ) ) ; } } }
  else  {
    for ( uint8_t i = 0 ; i < secretdatasolesize ; ++  i ) {
      if  ( streambuf_bufbitsize  ( me  ) < 2 ) {
      streambuf_buf ( me  ) or_eq ( ( ( * encrypteddata ) [ i ] ) <<
        streambuf_bufbitsize  ( me  ) ) ;
      streambuf_bufbitsize  ( me  ) +=  6 ; }
    else  {
      uint8_t const to_write  = ( ( ( * encrypteddata ) [ i ] ) <<
        streambuf_bufbitsize  ( me  ) ) bitor streambuf_buf ( me  ) ;
        size_t  writen_count  ;
        writen_count = fwrite ( & to_write , 1 , 1 ,
          streambuf_file  ( me  ) ) ;
      if ( writen_count < 1 ) {
        clearerr ( streambuf_file  ( me  ) ) ; 
        ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
          ( strcp ) & u8"streambuf_write6: ошибка записи байта" :
          ( strcp ) & "streambuf_write6: byte write error" ) ;
        longjmp(ns_shifr  . jump,1); }
      
        // + 6 - 8
        streambuf_bufbitsize  ( me  ) -= 2 ;
        streambuf_buf ( me  ) = ( ( * encrypteddata ) [ i ] ) >>
          ( 6 - streambuf_bufbitsize  ( me  ) ) ;  } } } }

static inline void  streambuf_writeflushzero ( t_streambuf * const restrict me ) {
  if  ( streambuf_bufbitsize  ( me  ) ) {
    size_t  writen_count  ;
      writen_count = fwrite ( & streambuf_buf ( me  ) , 1 , 1 ,
        streambuf_file  ( me  ) ) ;
    if ( writen_count < 1 ) {
      clearerr ( streambuf_file  ( me  ) ) ; 
      ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
        ( strcp ) & u8"streambuf_writeflushzero: ошибка записи байта" :
        ( strcp ) & "streambuf_writeflushzero: byte write error" ) ;
      longjmp(ns_shifr  . jump,1); }
    streambuf_bufbitsize  ( me  ) = 0 ; }
  if ( ns_shifr  . flagtext and streambuf_bytecount ( me  ) )  {
    streambuf_bytecount ( me  ) = 0 ;
    char  buf2 = '\n' ;
    size_t  const writen_count = fwrite ( & buf2 , 1 , 1 , 
      streambuf_file  ( me  ) ) ;
    if ( writen_count < 1 ) {
      clearerr ( streambuf_file  ( me  ) ) ; 
      ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
        ( strcp ) & u8"streambuf_writeflushzero: ошибка записи байта" :
        ( strcp ) & "streambuf_writeflushzero: byte write error" ) ;
      longjmp(ns_shifr  . jump,1); } } }
  
// версия 6 пишу три бита для расшифровки
// version 6 write three bits to decode
static inline void  streambuf_write3bits ( t_streambuf * const restrict me  ,
  uint8_t const encrypteddata ) {
    if  ( streambuf_bufbitsize  ( me  ) < 5 ) {
      streambuf_buf ( me  ) or_eq (    encrypteddata    <<
        streambuf_bufbitsize  ( me  )) ;
      streambuf_bufbitsize  ( me  ) +=  3 ; }
    else  {
      uint8_t const to_write  = (    encrypteddata   <<
        streambuf_bufbitsize  ( me  ) ) bitor streambuf_buf ( me  ) ;
      size_t  writen_count  ;
        writen_count = fwrite ( & to_write , 1 , 1 ,
          streambuf_file  ( me  ) ) ;
      if ( writen_count < 1 ) {
        clearerr ( streambuf_file  ( me  ) ) ; 
        ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
          ( strcp ) & u8"streambuf_write3bits: ошибка записи байта" :
          ( strcp ) & "streambuf_write3bits: byte write error" ) ;
        longjmp(ns_shifr  . jump,1); }
      // + 3 - 8
      streambuf_bufbitsize  ( me  ) -= 5 ;
      streambuf_buf ( me  ) =    encrypteddata   >>
        ( 3 - streambuf_bufbitsize  ( me  ) ) ; } }

# undef streambuf_file
# define  streambuf_file  streambuf_file_pri
# undef streambuf_buf
# define  streambuf_buf  streambuf_buf_pri
# undef streambuf_bufbitsize
# define  streambuf_bufbitsize  streambuf_bufbitsize_pri
# undef streambuf_bytecount
# define  streambuf_bytecount  streambuf_bytecount_pri

void  shifr_encode4 ( void ) {
    int charcount = 0 ;
    uint8_t old_last_data = 0 ;
    uint8_t old_last_sole = 0 ;
    do {
      char buf ;
      size_t readcount = fread ( & buf , 1 , 1 , ns_shifr  . filefrom ) ;
      if ( readcount == 0 ) {
        if ( ferror ( ns_shifr  . filefrom ) ) {
          clearerr ( ns_shifr  . filefrom ) ;
          ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
            ( strcp ) & u8"ошибка чтения файла" :
            ( strcp ) & "error reading file" ) ;
          longjmp ( ns_shifr  . jump  , 1 ) ; }
        break ; }
      uint8_t const secretdata  [ 4 ] = { [ 0 ]  = buf  bitand 0x3 ,
        [ 1 ] = ( buf >>  2 ) bitand 0x3 , [ 2 ] = ( buf >>  4 ) bitand 0x3 ,
        [ 3 ] = ( buf >>  6 ) bitand 0x3 } ;
      uint8_t secretdatasole  [ 4 ] ;
      datasole ( & secretdata , & secretdatasole , 4 )  ;
      // после подсоления, данные переворачиваем предыдущим ксором
      data_xor ( & old_last_data , & old_last_sole , & secretdatasole , 4 )  ;
      uint8_t encrypteddata [ 4 ] ;
      crypt_decrypt ( & secretdatasole , & ns_shifr  . shifr , & encrypteddata ,
        4 ) ;
// 2^16 ^ 1/3 = 40.32
// 2^16 % 40 = 0 .. 39
// 2^16 / 40 = 1638.4
// 1639 ^ 1/2 = 40.48
// 1639 % 40 = 0 .. 39
// 1639 / 40 = 40.97
// делаем [0] % 40 , [1] % 40 , [2] % 41
// 'R' = 82 .. 'z' = 122
      size_t writecount ;
      if  ( ns_shifr  . flagtext  ) {
        uint16_t buf16 = ((uint16_t)( encrypteddata [ 0 ] bitand 0xf )) bitor
          ( ((uint16_t)( encrypteddata [ 1 ] bitand 0xf )) << 4  )  bitor
          ( ((uint16_t)( encrypteddata [ 2 ] bitand 0xf )) << 8  )  bitor
          ( ((uint16_t)( encrypteddata [ 3 ] bitand 0xf )) << 12  ) ;
        char buf3 [ 4 ] ;
        buf3 [ 0 ] = 'R' + ( buf16 % 40 ) ;
        buf16 /= 40 ;
        buf3 [ 1 ] = 'R' + ( buf16 % 40 ) ;
        buf16 /= 40 ;
        buf3 [ 2 ] = 'R' + buf16 ;
        charcount += 3 ;
        if ( charcount == 60 )  {
          charcount = 0 ;
          buf3  [ 3 ] = '\n' ;
          writecount = fwrite ( & ( buf3 [ 0 ] ) , 4 , 1 , ns_shifr  . fileto ) ; }
        else
          writecount = fwrite ( & ( buf3 [ 0 ] ) , 3 , 1 , ns_shifr  . fileto ) ; }
      else {
        char buf2 [ 2 ] = {
          [ 0 ] = ((uint16_t)( encrypteddata [ 0 ] & 0xf )) bitor
            ( ((uint16_t)( encrypteddata [ 1 ] & 0xf )) << 4  ) ,
          [ 1 ] = ((uint16_t)( encrypteddata [ 2 ] & 0xf )) bitor
            ( ((uint16_t)( encrypteddata [ 3 ] & 0xf )) << 4 ) } ;
        writecount = fwrite ( & (buf2[0]) , 2 , 1 , ns_shifr  . fileto ) ; }
      if ( writecount == 0 ) {
        ns_shifr  . string_exception  = ( ns_shifr . localerus ?
          ( strcp ) & u8"ошибка записи в файл" :
          ( strcp ) & "error writing to file" ) ;
        longjmp(ns_shifr  . jump,1); }
    } while ( true ) ; 
    if ( ns_shifr  . flagtext and charcount ) {
      char buf = '\n' ;
      size_t  writecount = fwrite ( & buf , 1 , 1 , ns_shifr  . fileto ) ;
      if ( writecount == 0 ) {
        ns_shifr  . string_exception  = ( ns_shifr . localerus ?
          ( strcp ) & u8"ошибка записи в файл" :
          ( strcp ) & "error writing to file" ) ;
        longjmp(ns_shifr  . jump,1); } } }

t_streambuf shifr_filebuffrom ;
t_streambuf shifr_filebufto ;

void  shifr_encode6 ( void ) {
  // версия 6 шифруем ...
  int bitscount  = 0 ;
  uint8_t secretdata  [ 4 ] ;
  uint8_t secretdatasole  [ 3 ] ;
  uint8_t secretdatasolesize  ;
  uint8_t encrypteddata [ 3 ] ;
  bool  feof  = false ;
  uint8_t old_last_data = 0 ;
  uint8_t old_last_sole = 0 ;
  uint8_t addr_sole_xor_crypt_write ;
  do {
    unsigned  char buf ;
    size_t readcount = fread ( & buf , 1 , 1 , ns_shifr  . filefrom ) ;
    if ( readcount == 0 ) {
      if ( ferror ( ns_shifr  . filefrom ) ) {
        clearerr ( ns_shifr  . filefrom ) ;
        ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
          ( strcp ) & u8"ошибка чтения файла" :
          ( strcp ) & "error reading file" ) ;
        longjmp(ns_shifr  . jump,1); }
      buf = 0 ;
      feof  = true  ; 
      if  ( bitscount ==  0 ) {
        secretdatasolesize  = 0 ;
        break ; }
      secretdatasolesize  = 1 ;
      if  ( bitscount ==  1 )
        secretdata [ 0 ] = secretdata [ 3 ] ;
      else
        secretdata [ 0 ] = secretdata [ 2 ] ;
      addr_sole_xor_crypt_write =  1  ;
      goto  sole_xor_crypt_write  ;
      addr_sole_xor_crypt_write1  : ;
      break ; }
    switch  ( bitscount  ) {
      case  0 :
        // <= [ [1 0] [2 1 0] [2 1 0] ]
        secretdata [ 0 ]  = buf  bitand 0x7 ;
        secretdata [ 1 ] = ( buf >>  3 ) bitand 0x7 ;
        secretdata [ 2 ] = buf >>  6 ;
        bitscount  = 2 ; // 0 + 8 - 6
        secretdatasolesize  = 2 ;
        break ;
      case  1 : 
        // <= [ [2 1 0] [2 1 0] [2 1] ] <= [ [0]
        secretdata [ 0 ] = secretdata [ 3 ] bitor (( buf  bitand 0x3 )<<1) ;
        secretdata [ 1 ] = ( buf >>  2 ) bitand 0x7 ;
        secretdata [ 2 ] = buf >>  5 ;
        bitscount  = 0 ;   // 1 + 8 - 9
        secretdatasolesize  = 3 ;
        break ;
      case  2 :
        // <= [ [0] [2 1 0] [2 1 0] [2] ] <= [ [1 0] ..
        secretdata [ 0 ] = secretdata [ 2 ] bitor (( buf  bitand 0x1 )<<2) ;
        secretdata [ 1 ] = ( buf >>  1 ) bitand 0x7 ;
        secretdata [ 2 ] = ( buf >>  4 ) bitand 0x7 ;
        secretdata [ 3 ] = buf >>  7 ;
        bitscount  = 1 ; // 2 + 8 - 9
        secretdatasolesize  = 3 ;
        break ;
      default :
        fprintf ( stderr  , ( ns_shifr . localerus ?
          u8"неожиданное значение bitscount = %d\n":
          "unexpected value bitscount = %d\n" ) , bitscount ) ;
        ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
          ( strcp ) & u8"неожиданное значение bitscount" :
          ( strcp ) & "unexpected value bitscount" ) ;
        longjmp ( ns_shifr  . jump  , 1 ) ; }
    addr_sole_xor_crypt_write =  0  ;
    goto  sole_xor_crypt_write  ;
    addr_sole_xor_crypt_write0  : ;
  } while ( not feof ) ; 
  streambuf_writeflushzero ( & shifr_filebufto ) ;
  return  ;
sole_xor_crypt_write  :
  datasole6 ( & secretdata , & secretdatasole , secretdatasolesize )  ;
  // после подсоления, данные переворачиваем предыдущим ксором
  data_xor6 ( & old_last_data , & old_last_sole , & secretdatasole ,
    secretdatasolesize )  ;
  crypt_decrypt ( & secretdatasole , & ns_shifr  . shifr6 , & encrypteddata ,
    secretdatasolesize ) ;
  streambuf_write6 ( & shifr_filebufto , & encrypteddata , secretdatasolesize ,
    ns_shifr  . flagtext )  ;
  if (  addr_sole_xor_crypt_write ==  0 ) goto  addr_sole_xor_crypt_write0  ;
  goto  addr_sole_xor_crypt_write1  ; }

void shifr_decode4  ( void  ) {
  uint8_t old_last_data = 0 ;
  uint8_t old_last_sole = 0 ;
  do {
    char buf [ 2 ] ;
    size_t readcount ;
    if  ( ns_shifr  . flagtext  ) {
// 2^16 ^ 1/3 = 40.32
// 2^16 % 40 = 0 .. 39
// 2^16 / 40 = 1638.4
// 1639 ^ 1/2 = 40.48
// 1639 % 40 = 0 .. 39
// 1639 / 40 = 40.97
// делаем [0] % 40 , [1] % 40 , [2] % 41
// 'R' = 82 .. 'z' = 122
      // читаем три буквы ' a 1 b' -> декодируем в два байта "XY"
      // reads three letters ' a 1 b' -> decode to two bytes "XY"
      char  buf3  [ 3 ] ;
      uint8_t buf3index = 0 ;
      do {
        do {
          readcount = fread ( & ( buf3 [ buf3index ] ) , 1 , 1 ,
            ns_shifr  . filefrom ) ;
          if ( readcount == 0 ) {
            if ( feof ( ns_shifr  . filefrom ) ) return ;
            ns_shifr  . string_exception  = ( ns_shifr . localerus ?
              ( strcp ) & u8"ошибка чтения данных" :
              ( strcp ) & "error data reading" ) ;
            longjmp ( ns_shifr  . jump  , 1 ) ; }
        } while ( buf3  [ buf3index ] < 'R' or
          buf3  [ buf3index ] > 'z' ) ;
        ++  buf3index ;
      } while ( buf3index < 3 ) ;
      uint16_t u16 = (  ( uint16_t  ) ( buf3  [ 0 ] - 'R' ) ) +
        40U * ( ( ( uint16_t  ) ( buf3  [ 1 ] - 'R' ) ) +
        40U * ( ( uint16_t  ) ( buf3  [ 2 ] - 'R' ) ) ) ;
      buf [ 0 ] = u16 bitand 0xff ;
      buf [ 1 ] = u16 >> 8 ; }
    else {
        readcount = fread ( & ( buf [ 0 ] ) , 1 , 2 , ns_shifr  . filefrom ) ;
        if ( readcount < 2 ) {
          if ( feof ( ns_shifr  . filefrom  ) ) break ;
          if ( ferror ( ns_shifr  . filefrom ) ) {
            clearerr ( ns_shifr  . filefrom ) ;
            ns_shifr  . string_exception  = ( ns_shifr . localerus ?
              ( strcp ) & u8"ошибка чтения файла" :
              ( strcp ) & "error reading file" ) ;
            longjmp(ns_shifr  . jump,1); }
          break ; } }
      uint8_t secretdata  [ 4 ] = { [ 0 ] = buf [ 0 ] bitand  0xf ,
        [ 1 ] = ( buf [ 0 ] >>  4 ) bitand  0xf ,
        [ 2 ] = buf [ 1 ] bitand  0xf ,
        [ 3 ] = ( buf [ 1 ] >>  4 ) bitand  0xf  } ;
      uint8_t decrypteddata [ 4 ] ;
      decrypt_sole ( & secretdata , & ns_shifr  . deshi , & decrypteddata , 4 ,
        & old_last_sole , & old_last_data ) ;
      buf [ 0 ] = ( decrypteddata [ 0 ] bitand 0x3  ) bitor
        ( ( decrypteddata [ 1 ] bitand 0x3  ) << 2  )
        bitor ( ( decrypteddata [ 2 ] bitand 0x3  ) <<  4 ) bitor
        ( ( decrypteddata [ 3 ] bitand 0x3  ) << 6  ) ;
      size_t writecount = fwrite ( & (buf[0]) , 1 , 1 , ns_shifr  . fileto ) ;
      if ( writecount == 0 ) {
        if ( ferror ( ns_shifr  . fileto ) ) {
          clearerr ( ns_shifr  . fileto ) ;
          ns_shifr  . string_exception  = ( ns_shifr . localerus ?
            ( strcp ) & u8"ошибка записи файла" :
            ( strcp ) & "error writing file" ) ;
          longjmp(ns_shifr  . jump,1); }
        break ; }
    } while ( true ) ; }

void shifr_decode6 ( void ) {
  uint8_t secretdata [ 1 ] ;
  uint8_t old_last_data = 0 ;
  uint8_t old_last_sole = 0 ;
  while ( not isEOFstreambuf_read6bits ( & shifr_filebuffrom ,
    & ( secretdata [ 0 ] ) ) ) {
    uint8_t decrypteddata [ 1 ] ;
    decrypt_sole6 ( & secretdata , & ns_shifr  . deshi6 , & decrypteddata , 1 ,
      & old_last_sole , & old_last_data ) ;
    streambuf_write3bits ( & shifr_filebufto , decrypteddata [ 0 ] ) ; } }

// inits array [ 0..15 , 0..14 , ... , 0..2 , 0..1 ]
void  shifr_generate_pass4 ( void ) {
  uint8_t * j = & ( ns_shifr . raspr4  . dice [ 0 ] ) ;
  for ( uint8_t i  = 16 ; i >= 2 ; -- i , ++ j )
    ( * j ) = rand  ( ) % i ; }

// inits array [ 0..63 , 0..62 , ... , 0..2 , 0..1 ]
void  shifr_generate_pass6 ( void ) {
  uint8_t * j = & ( ns_shifr . raspr6  . dice [ 0 ] ) ;
  for ( uint8_t i  = 64 ; i >= 2 ; -- i , ++ j )
    ( * j ) = rand  ( ) % i ; }

// [ 0..15 , 0..14 , 0..13 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ] =
// = x + y * 16 + z * 16 * 15 + ... + u * 16! / 2 / 3 + v * 16! / 2 = 0 .. 16!-1
void  shifr_pass_to_array4 ( void ) {
  number_set0 ( 6 ) ( & ns_shifr . raspr4  . pass  ) ;
  number_type ( 6 ) mu  ;
  number_set_byte ( 6 ) ( & mu , 1 ) ;
  uint8_t in = 0 ;
  do {
    { number_type ( 6 ) mux = mu ;
      // re += dice [ in ] * mu ;
      number_mul_byte ( 6 ) ( & mux  ,  ns_shifr . raspr4  . dice [ in ] ) ;
      number_add  ( 6 ) ( & ns_shifr . raspr4  . pass , & mux ) ; }
    //$mu *=  16 - $in ;
    number_mul_byte ( 6 ) ( & mu , 16 - in  ) ;
    ++  in ;
  } while ( in < 15 ) ; }

// [ 0..63 , 0..62 , 0..61 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ] =
// = x + y * 64 + z * 64 * 63 + ... + u * 64! / 2 / 3 + v * 64! / 2 = 0 .. 64!-1
void  shifr_pass_to_array6 ( void ) {
  number_set0 ( 37 ) ( & ns_shifr . raspr6  . pass  ) ;
  number_type ( 37 ) mu  ;
  number_set_byte ( 37 ) ( & mu , 1 ) ;
  uint8_t in = 0 ;
  do {
    { number_type ( 37 ) mux = mu ;
      // re += dice [ in ] * mu ;
      number_mul_byte ( 37 ) ( & mux  ,  ns_shifr . raspr6  . dice [ in ] ) ;
      number_add  ( 37 ) ( & ns_shifr . raspr6  . pass , & mux ) ; }
    //$mu *=  64 - $in ;
    number_mul_byte ( 37 ) ( & mu , 64 - in  ) ;
    ++  in ;
  } while ( in < 63 ) ; }

# define  shifr_number_def_princ( N ) \
void  shifr_number##N##_princ ( number_type ( N ) const * const restrict  np ,  \
  FILE * const fs ) { \
  fputs ( "[ " , fs ) ; \
  for ( int8_t i = N ; i ; ) {  \
    -- i ;  \
    fprintf ( fs  , "%x , " , number_elt_copy ( N ) ( np , i ) ) ; }  \
  fputs ( "]" , fs ) ; }
# define  number_def_princ shifr_number_def_princ

# ifdef SHIFR_DEBUG
number_def_princ  ( 6 )
number_def_princ  ( 37 )
# endif
