// Шифр ©2020 Глебов А.Н.
// Shifr ©2020 Glebe A.N.

# include <stdio.h>
# include <stdlib.h>
# include <errno.h>

# include "inline.h"

# define  number_array  shifr_number_array_pub

# define  shifr_number_def_set0( N ) \
  void shifr_number ## N ## _set0  ( number_type  ( N ) * const restrict np ) { \
    memset  ( & ( ( number_array  ( np  ) ) [ 0 ] ) , 0 , N ) ; }
# define  number_def_set0 shifr_number_def_set0

# define  shifr_number_def_mul_byte(  N ) \
void  shifr_number ## N ## _mul_byte ( number_type ( N ) * const restrict  np  , \
  uint8_t const byte ) {  \
  if ( byte == 0 ) {  \
    number_set0 ( N ) ( np  ) ; \
    return  ; } \
  if ( byte == 1 )  \
    return ; \
  uint8_t per = 0 ; \
  { uint8_t i = 0 ; \
    do { \
      uint16_t  x = ( ( uint16_t  ) ( number_elt_copy ( N ) ( np  , i ) ) ) * \
        ( ( uint16_t  ) byte  ) + ( ( uint16_t  ) per ) ; \
      number_array  ( np  ) [ i ] = x bitand 0xff ; \
      per = x >>  8 ; \
      ++  i ; \
    } while ( i < N ) ; } }
# define  number_def_mul_byte shifr_number_def_mul_byte

number_def_set0 ( number_size2 )
number_def_mul_byte ( number_size2 )
number_def_set0 ( number_size3 )
number_def_mul_byte ( number_size3 )
# undef number_array
  
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
      ( * old_last_sole ) = (  data_sole bitand  0x3 ) xor ( * old_last_data ) ; }
    ( * old_last_data ) = ( * ide ) ;
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
      ( * stringi ) = ( * letters ) [ \
        number_div_mod ( N ) ( & password , letterscount ) ] ;  \
      ++  stringi ; \
    } while ( number_not_zero ( N ) ( & password ) ) ; }  \
  ( * stringi ) = '\00' ;  }
# define  password_to_string_templ_def  shifr_password_to_string_templ_def
password_to_string_templ_def  ( number_size2 )
password_to_string_templ_def  ( number_size3 )

# define  shifr_string_to_password_templ_def( N ) \
void  shifr_string_to_password  ##  N ##  _templ ( t_ns_shifr * const ns_shifrp , \
  strcp const string , number_type ( N ) * const restrict password ,  \
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
      if ( ( * stringi ) == ( * letters ) [ i ] ) \
        goto found ; \
    } while ( i ) ; \
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?  \
      ( strcp ) & u8"неправильная буква в пароле" : \
      ( strcp ) & "wrong letter in password" ) ;  \
    longjmp ( ns_shifrp  -> jump  , 1 ) ; \
found : ; \
    { number_type ( N ) tmp = mult ;  \
      number_mul_byte ( N ) ( & tmp , i + 1 ) ; \
      number_add ( N ) ( &  pass  , & tmp )  ; }  \
    number_mul_byte ( N ) ( & mult , letterscount ) ; \
    ++  stringi ; \
  } while ( ( * stringi ) not_eq '\00' ) ;  \
  ( * password  ) = pass ; }
# define  string_to_password_templ_def  shifr_string_to_password_templ_def
string_to_password_templ_def  ( number_size2 )
string_to_password_templ_def  ( number_size3 )

static  void datasole ( arrcp const secretdata , arrp const secretdatasole ,
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
    ( * ids ) =
      ( ( * id  ) <<  2 ) bitor
      ( ran bitand  0x3 ) ;
    ran >>= 2 ;
  } while ( id not_eq & ( ( * secretdata  ) [ 0 ] ) ) ; }

static void datasole6 ( arrcp const secretdata , arrp const secretdatasole ,
  size_t const data_size ) {
/*fprintf ( stderr  , u8"datasole6:data_size = %zu\n" , data_size ) ;
fputs ( u8"datasole6:secretdata = [ " , stderr  ) ;
{size_t ii = 0 ;while(ii<data_size){fprintf ( stderr  , u8"0x%x , " , ( * secretdata  ) [ ii ] ) ;++ii;}}
fputs ( u8"]\n" , stderr  ) ;*/
  uint8_t const * restrict  id = &  ( ( * secretdata  ) [ data_size ] ) ;
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ data_size ] ) ;
  int ran = rand ( )  ;
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 101 =>
    //   101_000 или 101_001 или ... или 101_111
    // в таблице всё рядом, 8 вариантов равномерно распределены
    ( * ids ) =
      ( ( * id  ) <<  3 ) bitor
      ( ran bitand  0x7 ) ;
    ran >>= 3 ;
  } while ( id not_eq & ( ( * secretdata  ) [ 0 ] ) ) ;
/*fputs ( u8"datasole6:secretdatasole = [ " , stderr  ) ;
{size_t ii = 0 ;while(ii<data_size){fprintf ( stderr  , u8"0x%x , " , ( * secretdatasole  ) [ ii ] ) ;++ii;}}
fputs ( u8"]\n" , stderr  ) ;*/
 }

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

void  data_xor6  ( uint8_t * const restrict  old_last_data ,
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
void set_keypress ( t_ns_shifr * const ns_shifrp ) {
  if  ( tcgetattr ( 0 , & ns_shifrp  -> stored_termios  ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      u8"ошибка чтения tcgetattr : %s\n" :
      "error read tcgetattr : %s\n" ) ,se ) ;
    ns_shifrp  -> string_exception  = ( strcp ) se ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  struct termios new_termios = ns_shifrp -> stored_termios  ;
  new_termios.c_lflag  and_eq ~ ( ECHO bitor ICANON ) ;
  new_termios.c_cc  [ VMIN  ] = 1 ;  
  new_termios.c_cc  [ VTIME ] = 0 ; 
  if  ( tcsetattr ( 0 , TCSANOW , & new_termios ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      u8"ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifrp  -> string_exception  = ( strcp ) se ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; } }
 
// Восстановление дефолтного состояния
void reset_keypress ( t_ns_shifr * const ns_shifrp ) {
  if  ( tcsetattr ( 0 , TCSANOW , & ns_shifrp -> stored_termios ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      u8"ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifrp  -> string_exception  = ( strcp ) se ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; } }

# define  streambuf_file  shifr_streambuf_file_pub
# define  streambuf_buf  shifr_streambuf_buf_pub
# define  streambuf_bufbitsize  shifr_streambuf_bufbitsize_pub
# define  streambuf_bytecount  shifr_streambuf_bytecount_pub

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
static inline bool  isEOFstreambuf_read6bits ( t_ns_shifr * const ns_shifrp ,
  t_streambuf * const restrict me  , uint8_t * const encrypteddata ) {
  if  ( ( not ( ns_shifrp  -> flagtext ) ) and
    streambuf_bufbitsize  ( me  ) >= 6 ) {
    streambuf_bufbitsize  ( me  ) -=  6 ;
    ( * encrypteddata ) = streambuf_buf ( me  ) bitand
      ( 0x40 - 1 ) ;
    streambuf_buf ( me  ) >>= 6 ;
    return  false ; }
  uint8_t buf ;
  { size_t  const nreads  = fread ( & buf , 1 , 1 , streambuf_file  ( me  ) ) ;
    if ( nreads ==  0 ) {
      if  ( feof  ( streambuf_file  ( me  ) ) )
        return  true  ;
      if  ( ferror  ( streambuf_file  ( me  ) ) ) {
        clearerr ( streambuf_file  ( me  ) ) ;
        ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? 
          ( strcp ) &
          u8"isEOFstreambuf_read6bits: ошибка чтения шести бит" :
          ( strcp ) & "isEOFstreambuf_read6bits: six bits read error" ) ;
        longjmp ( ns_shifrp  -> jump  , 1 ) ; } } } // nreads
  if  ( ns_shifrp  -> flagtext  ) {
    // читаем одну букву ';'-'z' -> декодируем в шесть бит
    // reads one letter ';'-'z' -> decode to six bits
    while ( ( buf < ( ( uint8_t ) ';' ) ) or
      ( buf > ( ( uint8_t ) 'z' ) ) ) {
      { size_t  const nreads  = fread ( & buf , 1 , 1 , streambuf_file  ( me  ) ) ;
        if ( nreads ==  0 ) {
          if  ( feof  ( streambuf_file  ( me  ) ) )
            return  true  ;
          if  ( ferror  ( streambuf_file  ( me  ) ) ) {
            clearerr ( streambuf_file  ( me  ) ) ;
            ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? 
              ( strcp ) &
              u8"isEOFstreambuf_read6bits: ошибка чтения шести бит из текста" :
              ( strcp ) &
              "isEOFstreambuf_read6bits: six bits read error from text" ) ;
            longjmp ( ns_shifrp  -> jump  , 1 ) ; } } } // nreads
          }
    ( * encrypteddata ) = letter_to_bits6 ( buf ) ; }
  else  {
    ( * encrypteddata ) = ( streambuf_buf ( me  ) bitor 
        ( buf <<  streambuf_bufbitsize  ( me  ) ) ) bitand
      ( 0x40 - 1 )  ;
    streambuf_buf ( me  ) = buf >>
      ( 6 - streambuf_bufbitsize  ( me  ) ) ;
    streambuf_bufbitsize  ( me  ) +=  2 ; } // + 8 - 6
  return  false ; }
        
// пишу по шесть бит
// secretdatasolesize - количество шести-битных отделов (2 или 3)
// encrypteddata - массив шести-битных чисел
// I write in six bits
// secretdatasolesize - the number of six-bit divisions (2 or 3)
// encrypteddata - array of six-bit numbers
static void  streambuf_write6 ( t_ns_shifr * const ns_shifrp ,
  t_streambuf * const restrict me  , uint8_t const (  * const encrypteddata ) [ 3 ] ,
  uint8_t const secretdatasolesize , bool const  flagtext ) {
  if  ( flagtext  ) {
    uint8_t i = 0 ;
    do {
      char  buf2  = bits6_to_letter ( ( * encrypteddata ) [ i ] ) ;
        size_t  writen_count  ;
        writen_count  = fwrite  ( & buf2  , 1 , 1 , streambuf_file  ( me  ) ) ;
        if  ( writen_count  ==  0 ) {
          clearerr  ( streambuf_file  ( me  ) ) ; 
          ns_shifrp  -> string_exception  = ( ns_shifrp  -> localerus ? 
            ( strcp ) & u8"streambuf_write6: ошибка записи байта"  :
            ( strcp ) & "streambuf_write6: byte write error" ) ;
          longjmp ( ns_shifrp  -> jump  , 1 ) ; }
        ++  streambuf_bytecount ( me  ) ;
        if  ( streambuf_bytecount ( me  ) >=  60  ) {
          streambuf_bytecount ( me  ) = 0 ;
          buf2  = '\n'  ;
          writen_count  = fwrite  ( & buf2  , 1 , 1 ,
            streambuf_file  ( me  ) ) ; }
      ++  i ;
    } while ( i < secretdatasolesize ) ; }
  else  {
    uint8_t i = 0 ;
    do {
      if  ( streambuf_bufbitsize  ( me  ) < 2 ) {
        streambuf_buf ( me  ) or_eq
          ( ( ( * encrypteddata ) [ i ] ) << streambuf_bufbitsize  ( me  ) ) ;
        streambuf_bufbitsize  ( me  ) +=  6 ; }
      else  {
        uint8_t const to_write  = ( ( ( * encrypteddata ) [ i ] ) <<
          streambuf_bufbitsize  ( me  ) ) bitor streambuf_buf ( me  ) ;
        size_t  writen_count  ;
        writen_count = fwrite ( & to_write , 1 , 1 , streambuf_file  ( me  ) ) ;
        if ( writen_count < 1 ) {
          clearerr ( streambuf_file  ( me  ) ) ; 
          ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? 
            ( strcp ) & u8"streambuf_write6: ошибка записи байта" :
            ( strcp ) & "streambuf_write6: byte write error" ) ;
          longjmp ( ns_shifrp  -> jump  , 1 ) ; }
        // + 6 - 8
        streambuf_bufbitsize  ( me  ) -= 2 ;
        streambuf_buf ( me  ) = ( ( * encrypteddata ) [ i ] ) >>
          ( 6 - streambuf_bufbitsize  ( me  ) ) ;  } 
        ++  i ;
      } while ( i < secretdatasolesize ) ; } }

// пишу по шесть бит
// secretdatasolesize - количество шести-битных отделов (2 или 3)
// encrypteddata - массив шести-битных чисел
// I write in six bits
// secretdatasolesize - the number of six-bit divisions (2 or 3)
// encrypteddata - array of six-bit numbers
static void  streambuf_write3 ( t_ns_shifr * const ns_shifrp ,
  t_streambuf * const restrict me  , uint8_t const (  * const encrypteddata ) [ 3 ] ,
  uint8_t const secretdatasolesize , bool const  flagtext ,
  uint8_t * restrict  * const output_bufferp , size_t * const writesp ,
  size_t  const outputs ) {
  if  ( flagtext  ) {
    uint8_t i = 0 ;
    do {
      char  buf2  = bits6_to_letter ( ( * encrypteddata ) [ i ] ) ;
        if ( ( * writesp ) >= outputs ) {
          ns_shifrp  -> string_exception  = ( ns_shifrp  -> localerus ? 
            ( strcp ) & u8"streambuf_write3: переполнение буфера (flagtext)"  :
            ( strcp ) & "streambuf_write3: buffer overflow (flagtext)" ) ;
          longjmp ( ns_shifrp  -> jump  , 1 ) ; }
        ( * * output_bufferp ) = buf2 ;
        ++  ( * output_bufferp )  ;
        ++  ( * writesp ) ;
        ++  streambuf_bytecount ( me  ) ;
        if  ( streambuf_bytecount ( me  ) >=  60  ) {
          if ( ( * writesp ) >= outputs ) {
            ns_shifrp  -> string_exception  = ( ns_shifrp  -> localerus ? 
              ( strcp ) & u8"streambuf_write3: переполнение буфера для '\\n'"  :
              ( strcp ) & "streambuf_write3: buffer overflow for '\\n'" ) ;
            longjmp ( ns_shifrp  -> jump  , 1 ) ; }
          ( * * output_bufferp ) = '\n' ;
          ++  ( * output_bufferp )  ;
          ++  ( * writesp ) ;
          streambuf_bytecount ( me  ) = 0 ; }
      ++  i ;
    } while ( i < secretdatasolesize ) ; }
  else  {
    uint8_t i = 0 ;
    do {
      if  ( streambuf_bufbitsize  ( me  ) < 2 ) {
        streambuf_buf ( me  ) or_eq
          ( ( ( * encrypteddata ) [ i ] ) << streambuf_bufbitsize  ( me  ) ) ;
        streambuf_bufbitsize  ( me  ) +=  6 ; }
      else  {
        uint8_t const to_write  = ( ( ( * encrypteddata ) [ i ] ) <<
          streambuf_bufbitsize  ( me  ) ) bitor streambuf_buf ( me  ) ;
        if ( ( * writesp ) >= outputs ) {
          ns_shifrp  -> string_exception  = ( ns_shifrp  -> localerus ? 
            ( strcp ) & u8"streambuf_write3: переполнение буфера (flagdigit)"  :
            ( strcp ) & "streambuf_write3: buffer overflow (flagdigit)" ) ;
          longjmp ( ns_shifrp  -> jump  , 1 ) ; }
        ( * * output_bufferp ) = to_write ;
        ++  ( * output_bufferp )  ;
        ++  ( * writesp ) ;
        // + 6 - 8
        streambuf_bufbitsize  ( me  ) -= 2 ;
        streambuf_buf ( me  ) = ( ( * encrypteddata ) [ i ] ) >>
          ( 6 - streambuf_bufbitsize  ( me  ) ) ;  } 
        ++  i ;
      } while ( i < secretdatasolesize ) ; } }

void  streambuf_writeflushzero ( t_ns_shifr * const ns_shifrp ,
  t_streambuf * const restrict me ) {
/*fprintf ( stderr , u8"streambuf_writeflushzero:streambuf_bufbitsize  ( me  )=%u\n" ,
  (unsigned int)streambuf_bufbitsize  ( me  ) ) ;*/
  if  ( streambuf_bufbitsize  ( me  ) ) {
    size_t  writen_count  ;
      writen_count = fwrite ( & streambuf_buf ( me  ) , 1 , 1 ,
        streambuf_file  ( me  ) ) ;
    if ( writen_count < 1 ) {
      clearerr ( streambuf_file  ( me  ) ) ; 
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? 
        ( strcp ) & u8"streambuf_writeflushzero: ошибка записи байта" :
        ( strcp ) & "streambuf_writeflushzero: byte write error" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
    streambuf_bufbitsize  ( me  ) = 0 ; }
  if ( ns_shifrp  -> flagtext and streambuf_bytecount ( me  ) )  {
    streambuf_bytecount ( me  ) = 0 ;
    char  buf2 = '\n' ;
    size_t  const writen_count = fwrite ( & buf2 , 1 , 1 , 
      streambuf_file  ( me  ) ) ;
    if ( writen_count < 1 ) {
      clearerr ( streambuf_file  ( me  ) ) ; 
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? 
        ( strcp ) & u8"streambuf_writeflushzero: ошибка записи байта" :
        ( strcp ) & "streambuf_writeflushzero: byte write error" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; } } }
  
uint8_t streambuf_writeflushzero3 ( t_ns_shifr * const ns_shifrp ,
  arrps arrpsp ) {
//fprintf ( stderr  , u8"1.ns_shifrp -> bitscount = %d\n" , ns_shifrp -> bitscount ) ;
  uint8_t result  = 0 ;
  uint8_t * restrict  output_buffer = &((*  arrpsp  . p)[0]) ;
  if  ( ns_shifrp -> bitscount ==  0 )
    goto  lbreak ;
  uint8_t secretdatasolesize  = 1 ;
/*fprintf ( stderr  , u8"1.secretdatasolesize = %u\n" ,
  (unsigned int )secretdatasolesize ) ;*/
  if  ( ns_shifrp -> bitscount ==  1 )
    ns_shifrp -> secretdata [ 0 ] = ns_shifrp -> secretdata [ 3 ] ;
  else
    ns_shifrp -> secretdata [ 0 ] = ns_shifrp -> secretdata [ 2 ] ;
/*fprintf ( stderr  , u8"1.ns_shifrp -> secretdata = [ [0] = 0x%x ]\n" ,
  (unsigned int )(ns_shifrp -> secretdata [ 0 ]) ) ;*/

  datasole6 ( ( arrcp ) & ns_shifrp -> secretdata , & ns_shifrp -> secretdatasole ,
    secretdatasolesize )  ;
  // после подсоления, данные переворачиваем предыдущим ксором
  data_xor6 ( & ns_shifrp -> old_last_data , & ns_shifrp -> old_last_sole ,
    & ns_shifrp -> secretdatasole , secretdatasolesize )  ;
  uint8_t encrypteddata [ 3 ] ;
  crypt_decrypt ( & ns_shifrp -> secretdatasole , ( arrcp ) & ns_shifrp  -> shifr6 ,
    & encrypteddata , secretdatasolesize ) ;
  
  size_t  writes  = 0 ;
  streambuf_write3 ( ns_shifrp , & ns_shifrp -> filebufto ,
    ( uint8_t const ( * ) [ 3 ] ) & encrypteddata ,
    secretdatasolesize , ns_shifrp  -> flagtext , & output_buffer , & writes ,
    arrpsp . s )  ;
fprintf(stderr,u8"streambuf_writeflushzero3:writes=%zu\n",writes);
  ++  result  ;
/*fprintf(stderr,u8"streambuf_writeflushzero3:encrypteddata[0] = 0x%x\n",
  (unsigned int)(encrypteddata[0]));
fprintf(stderr,u8"streambuf_writeflushzero3:(*  arrpsp  . p)[0] = 0x%x\n",
  (unsigned int)((*  arrpsp  . p)[0]));*/
lbreak  : ;

  t_streambuf * const restrict me = & ns_shifrp ->  filebufto ;
fprintf ( stderr , u8"streambuf_writeflushzero3:streambuf_bufbitsize  ( me  )=%u\n" ,
  (unsigned int)streambuf_bufbitsize  ( me  ) ) ;

  if  ( streambuf_bufbitsize  ( me  ) ) {
    ( * output_buffer ) = streambuf_buf ( me  ) ;
    ++  output_buffer ;
    ++  result  ;
    streambuf_bufbitsize  ( me  ) = 0 ; }

  if ( ns_shifrp  -> flagtext and streambuf_bytecount ( me  ) )  {
    streambuf_bytecount ( me  ) = 0 ;
    ( * output_buffer ) = '\n' ;
    ++  output_buffer ;
    ++  result  ; }
  return  result  ; }

// версия 6 пишу три бита для расшифровки
// version 6 write three bits to decode
static inline void  streambuf_write3bits ( t_ns_shifr * const ns_shifrp ,
  t_streambuf * const restrict me  , uint8_t const encrypteddata ) {
    if  ( streambuf_bufbitsize  ( me  ) < 5 ) {
      streambuf_buf ( me  ) or_eq
        ( encrypteddata << streambuf_bufbitsize  ( me  )  ) ;
      streambuf_bufbitsize  ( me  ) +=  3 ; }
    else  {
      uint8_t const to_write  = ( encrypteddata   <<
        streambuf_bufbitsize  ( me  ) ) bitor
        streambuf_buf ( me  ) ;
      size_t  writen_count  ;
      writen_count = fwrite ( & to_write , 1 , 1 ,
        streambuf_file  ( me  ) ) ;
      if ( writen_count < 1 ) {
        clearerr ( streambuf_file  ( me  ) ) ; 
        ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? 
          ( strcp ) & u8"streambuf_write3bits: ошибка записи байта" :
          ( strcp ) & "streambuf_write3bits: byte write error" ) ;
        longjmp ( ns_shifrp  -> jump  , 1 ) ; }
      // + 3 - 8
      streambuf_bufbitsize  ( me  ) -= 5 ;
      streambuf_buf ( me  ) =  encrypteddata   >>
        ( 3 - streambuf_bufbitsize  ( me  ) ) ; } }

# undef streambuf_file
# undef streambuf_buf
# undef streambuf_bufbitsize
# undef streambuf_bytecount

// returns size loads & writes
size_io shifr_encrypt2  ( t_ns_shifr * const ns_shifrp , arrcps const input ,
  arrps const output  ) {
  uint8_t const * restrict  input_buffer = &((* input . cp)[0]) ;
  uint8_t * restrict  output_buffer = &((*  output  . p)[0]) ;
  size_t  reads = 0 ;
  size_t  writes  = 0 ;
  while ( reads < input . s and writes + 4 <= output . s ) {
    char const  buf = * input_buffer  ;
    ++  input_buffer  ;
    ++  reads ;
    uint8_t const secretdata  [ 4 ] = { [ 0 ]  = buf  bitand 0x3 ,
      [ 1 ] = ( buf >>  2 ) bitand 0x3 , [ 2 ] = ( buf >>  4 ) bitand 0x3 ,
      [ 3 ] = ( buf >>  6 ) bitand 0x3 } ;
    uint8_t secretdatasole  [ 4 ] ;
    datasole ( & secretdata , & secretdatasole , 4 )  ;
    // после подсоления, данные переворачиваем предыдущим ксором
    data_xor ( & ns_shifrp  -> old_last_data , & ns_shifrp  -> old_last_sole ,
      & secretdatasole , 4 )  ;
    uint8_t encrypteddata [ 4 ] ;
    crypt_decrypt ( & secretdatasole , ( arrcp ) & ns_shifrp  -> shifr ,
      & encrypteddata , 4 ) ;
// 2^16 ^ 1/3 = 40.32
// 2^16 % 40 = 0 .. 39
// 2^16 / 40 = 1638.4
// 1639 ^ 1/2 = 40.48
// 1639 % 40 = 0 .. 39
// 1639 / 40 = 40.97
// делаем [0] % 40 , [1] % 40 , [2] % 41
// 'R' = 82 .. 'z' = 122
    if  ( ns_shifrp  -> flagtext  ) {
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
      ns_shifrp  -> charcount += 3 ;
      if ( ns_shifrp  -> charcount == 60 )  {
        ns_shifrp  -> charcount = 0 ;
        buf3  [ 3 ] = '\n' ;
        memcpy  ( output_buffer , & ( buf3 [ 0 ] )  , 4 ) ;
        writes  +=  4 ;
        output_buffer +=  4 ; }
      else {
        memcpy  ( output_buffer , & ( buf3 [ 0 ] )  , 3 ) ;
        writes  +=  3 ;
        output_buffer +=  3 ; } }
    else {
      char buf2 [ 2 ] = {
        [ 0 ] = ((uint16_t)( encrypteddata [ 0 ] & 0xf )) bitor
          ( ((uint16_t)( encrypteddata [ 1 ] & 0xf )) << 4  ) ,
        [ 1 ] = ((uint16_t)( encrypteddata [ 2 ] & 0xf )) bitor
          ( ((uint16_t)( encrypteddata [ 3 ] & 0xf )) << 4 ) } ;
      memcpy  ( output_buffer , & ( buf2 [ 0 ] )  , 2 ) ;
      writes  +=  2 ;
      output_buffer +=  2 ; } }
  return  ( size_io ) { .i  = reads , .o  = writes  } ; }

/*
Finished buffer encryption, returns output_buffer size written
Заканчивает шифрование буфера, возвращает размер записаных данных.
*/
size_t  shifr_encrypt2_flush  ( t_ns_shifr * const ns_shifrp ,
  arrps const output ) {
# ifdef SHIFR_DEBUG
  if ( output . s == 0 ) {
    ns_shifrp ->  string_exception  = ( strcp ) &
      "shifr_encrypt2_flush:output . s == 0" ;
    longjmp ( ns_shifrp ->  jump  , 1 ) ; }
# endif // SHIFR_DEBUG
  if ( ns_shifrp  -> flagtext and ns_shifrp  -> charcount ) {
    ns_shifrp  -> charcount = 0 ;
    ( * output . p ) [ 0 ] = '\n' ;
    return  1 ; }
  return  0 ; }

// returns size loads & writes
size_io shifr_encrypt3  ( t_ns_shifr * const ns_shifrp , arrcps const input ,
  arrps const output  ) {
  uint8_t secretdatasolesize  ;
  uint8_t encrypteddata [ 3 ] ;
  size_t  reads = 0 ;
  size_t  writes  = 0 ;
  uint8_t const * restrict  input_buffer = &((* input . cp)[0]) ;
  uint8_t * restrict  output_buffer = &((*  output  . p)[0]) ;
  while ( reads < input . s and writes < output . s ) {
    unsigned  char buf = ( * input_buffer ) ;
    ++  input_buffer  ;
    ++  reads ;
//fprintf ( stderr  , u8"buf = 0x%x\n" , (unsigned int )buf ) ;
//fprintf ( stderr  , u8"0.ns_shifrp -> bitscount = %d\n" , ns_shifrp -> bitscount ) ;
    switch  ( ns_shifrp -> bitscount  ) {
    case  0 :
        // <= [ [1 0] [2 1 0] [2 1 0] ]
        ( ns_shifrp -> secretdata ) [ 0 ]  = buf  bitand 0x7 ;
        ( ns_shifrp -> secretdata ) [ 1 ] = ( buf >>  3 ) bitand 0x7 ;
        ( ns_shifrp -> secretdata ) [ 2 ] = buf >>  6 ;
        ns_shifrp -> bitscount  = 2 ; // 0 + 8 - 6
        secretdatasolesize  = 2 ;
fprintf ( stderr  , u8"0.ns_shifrp -> secretdata = [ [0] = 0x%x , [1] = 0x%x , [2] = 0x%x ]\n" ,
  (unsigned int )(ns_shifrp -> secretdata [ 0 ]) , (unsigned int )(ns_shifrp -> secretdata [ 1 ]) ,
 (unsigned int )( ns_shifrp -> secretdata [ 2 ]) ) ;
fprintf ( stderr  , u8"0.secretdatasolesize = %u\n" ,
  (unsigned int )secretdatasolesize ) ;
        break ;
    case  1 : 
        // <= [ [2 1 0] [2 1 0] [2 1] ] <= [ [0]
        ( ns_shifrp -> secretdata ) [ 0 ] = ( ns_shifrp -> secretdata ) [ 3 ] bitor
          (( buf  bitand 0x3 )<<1) ;
        ( ns_shifrp -> secretdata ) [ 1 ] = ( buf >>  2 ) bitand 0x7 ;
        ( ns_shifrp -> secretdata ) [ 2 ] = buf >>  5 ;
        ns_shifrp -> bitscount  = 0 ;   // 1 + 8 - 9
        secretdatasolesize  = 3 ;
        break ;
    case  2 :
        // <= [ [0] [2 1 0] [2 1 0] [2] ] <= [ [1 0] ..
        ( ns_shifrp -> secretdata ) [ 0 ] = ( ns_shifrp -> secretdata ) [ 2 ] bitor
          (( buf  bitand 0x1 )<<2) ;
        ( ns_shifrp -> secretdata ) [ 1 ] = ( buf >>  1 ) bitand 0x7 ;
        ( ns_shifrp -> secretdata ) [ 2 ] = ( buf >>  4 ) bitand 0x7 ;
        ( ns_shifrp -> secretdata ) [ 3 ] = buf >>  7 ;
        ns_shifrp -> bitscount  = 1 ; // 2 + 8 - 9
        secretdatasolesize  = 3 ;
        break ;
    default :
      fprintf ( stderr  , ( ns_shifrp -> localerus ?
        u8"неожиданное значение bitscount = %d\n":
        "unexpected value bitscount = %d\n" ) , ns_shifrp -> bitscount ) ;
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? 
        ( strcp ) & u8"неожиданное значение bitscount" :
        ( strcp ) & "unexpected value bitscount" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; } // switch  ( ns_shifrp -> bitscount  )
    datasole6 ( ( arrcp ) & ( ns_shifrp -> secretdata ) ,
      & ns_shifrp -> secretdatasole , secretdatasolesize )  ;
    // после подсоления, данные переворачиваем предыдущим ксором
    data_xor6 ( & ns_shifrp -> old_last_data , & ns_shifrp -> old_last_sole ,
      & ns_shifrp -> secretdatasole , secretdatasolesize )  ;
    crypt_decrypt ( & ns_shifrp -> secretdatasole , ( arrcp ) & ns_shifrp  -> shifr6 ,
      & encrypteddata , secretdatasolesize ) ;
fprintf ( stderr  ,
  u8"shifr_encrypt3:encrypteddata = [ [0] = 0x%x , [1] = 0x%x , [2] = 0x%x ]\n" ,
  (unsigned int )(encrypteddata [ 0 ]) , (unsigned int )(encrypteddata [ 1 ]) ,
 (unsigned int )( encrypteddata [ 2 ]) ) ;
fprintf(stderr,u8"shifr_encrypt3:0.writes=%zu\n",writes);
    streambuf_write3 ( ns_shifrp , & ns_shifrp -> filebufto ,
      ( uint8_t const ( * ) [ 3 ] ) & encrypteddata ,
      secretdatasolesize , ns_shifrp  -> flagtext , & output_buffer , & writes ,
      output . s )  ;
fprintf(stderr,u8"shifr_encrypt3:1.writes=%zu\n",writes);
    } // while
  return ( size_io ) { .i  = reads , .o  = writes  }  ; }

void  shifr_encrypt6 ( t_ns_shifr * const ns_shifrp ) {
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
    size_t readcount = fread ( & buf , 1 , 1 , ns_shifrp  -> filefrom ) ;
    if ( readcount == 0 ) {
      if ( ferror ( ns_shifrp  -> filefrom ) ) {
        clearerr ( ns_shifrp  -> filefrom ) ;
        ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? 
          ( strcp ) & u8"ошибка чтения файла" :
          ( strcp ) & "error reading file" ) ;
        longjmp ( ns_shifrp  -> jump  , 1 ) ; }
      buf = 0 ;
      feof  = true  ; 
//fprintf ( stderr  , u8"1.bitscount = %d\n" , bitscount ) ;
      if  ( bitscount ==  0 ) {
        //secretdatasolesize  = 0 ;
        break ; }
      secretdatasolesize  = 1 ;
/*fprintf ( stderr  , u8"1.secretdatasolesize = %u\n" ,
  (unsigned int )secretdatasolesize ) ;*/
      if  ( bitscount ==  1 )
        secretdata [ 0 ] = secretdata [ 3 ] ;
      else
        secretdata [ 0 ] = secretdata [ 2 ] ;
/*fprintf ( stderr  , u8"1.secretdata = [ [0] = 0x%x ]\n" ,
  (unsigned int )(secretdata [ 0 ]) ) ;*/
      addr_sole_xor_crypt_write =  1  ;
      goto  sole_xor_crypt_write  ;
      addr_sole_xor_crypt_write1  : ;
      break ; } // if ( readcount == 0 )
//fprintf ( stderr  , u8"buf = 0x%x\n" , (unsigned int )buf ) ;
//fprintf ( stderr  , u8"0.bitscount = %d\n" , bitscount ) ;
    switch  ( bitscount  ) {
    case  0 :
        // [ [0 1 2] [0 1 2] [0 1] ] =>
        secretdata [ 0 ]  = buf  bitand 0x7 ;
        secretdata [ 1 ] = ( buf >>  3 ) bitand 0x7 ;
        secretdata [ 2 ] = buf >>  6 ;
        bitscount  = 2 ; // 0 + 8 - 6
        secretdatasolesize  = 2 ;
/*fprintf ( stderr  , u8"0.secretdata = [ [0] = 0x%x , [1] = 0x%x , [2] = 0x%x ]\n" ,
  (unsigned int )(secretdata [ 0 ]) , (unsigned int )(secretdata [ 1 ]) ,
 (unsigned int )( secretdata [ 2 ]) ) ;
fprintf ( stderr  , u8"0.secretdatasolesize = %u\n" ,
  (unsigned int )secretdatasolesize ) ;*/
        break ;
    case  1 : 
        // .. [0] ] => [ [1 2] [0 1 2] [0 1 2] ] =>
        secretdata [ 0 ] = secretdata [ 3 ] bitor (( buf  bitand 0x3 )<<1) ;
        secretdata [ 1 ] = ( buf >>  2 ) bitand 0x7 ;
        secretdata [ 2 ] = buf >>  5 ;
        bitscount  = 0 ;   // 1 + 8 - 9
        secretdatasolesize  = 3 ;
        break ;
    case  2 :
        // .. [0 1] ] => [ [2] [0 1 2] [0 1 2] [0] ] =>
        secretdata [ 0 ] = secretdata [ 2 ] bitor (( buf  bitand 0x1 )<<2) ;
        secretdata [ 1 ] = ( buf >>  1 ) bitand 0x7 ;
        secretdata [ 2 ] = ( buf >>  4 ) bitand 0x7 ;
        secretdata [ 3 ] = buf >>  7 ;
        bitscount  = 1 ; // 2 + 8 - 9
        secretdatasolesize  = 3 ;
        break ;
    default :
        fprintf ( stderr  , ( ns_shifrp -> localerus ?
          u8"неожиданное значение bitscount = %d\n":
          "unexpected value bitscount = %d\n" ) , bitscount ) ;
        ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? 
          ( strcp ) & u8"неожиданное значение bitscount" :
          ( strcp ) & "unexpected value bitscount" ) ;
        longjmp ( ns_shifrp  -> jump  , 1 ) ; } // switch  ( bitscount  )
    addr_sole_xor_crypt_write =  0  ;
    goto  sole_xor_crypt_write  ;
    addr_sole_xor_crypt_write0  : ;
  } while ( not feof ) ; 
  streambuf_writeflushzero ( ns_shifrp , & ns_shifrp -> filebufto ) ;
  return  ;
sole_xor_crypt_write  :
  datasole6 ( ( arrcp ) & secretdata , & secretdatasole , secretdatasolesize )  ;
  // после подсоления, данные переворачиваем предыдущим ксором
  data_xor6 ( & old_last_data , & old_last_sole , & secretdatasole ,
    secretdatasolesize )  ;
  crypt_decrypt ( & secretdatasole , ( arrcp ) & ns_shifrp  -> shifr6 ,
    & encrypteddata , secretdatasolesize ) ;
  streambuf_write6 ( ns_shifrp , & ns_shifrp -> filebufto ,
    ( uint8_t const ( * ) [ 3 ] ) & encrypteddata ,
    secretdatasolesize , ns_shifrp  -> flagtext )  ;
  if (  addr_sole_xor_crypt_write ==  0 )
    goto  addr_sole_xor_crypt_write0  ;
  goto  addr_sole_xor_crypt_write1  ; }

// returns size loads & writes
size_io  shifr_decrypt2  ( t_ns_shifr * const ns_shifrp , arrcps const input ,
  arrps const output  ) {
  uint8_t const * restrict  input_buffer = &((* input . cp)[0]) ;
  uint8_t * restrict  output_buffer = &((*  output  . p)[0]) ;
  size_t  reads = 0 ;
  size_t  writes  = 0 ;
  while ( reads < input . s and writes < output . s ) {
    char buf [ 2 ] ;
    if  ( ns_shifrp  -> flagtext  ) {
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
      do {
        do {
          if ( reads >= input . s or writes >= output . s )
            goto Exit ;
          ( ns_shifrp  -> buf3 ) [ ns_shifrp  -> buf3index ] = ( * input_buffer ) ;
          ++  input_buffer  ;
          ++  reads ;
        } while ( ( ns_shifrp  -> buf3 ) [ ns_shifrp  -> buf3index ] < 'R' or
          ( ns_shifrp  -> buf3 ) [ ns_shifrp  -> buf3index ] > 'z' ) ;
        ++ ( ns_shifrp  -> buf3index ) ;
      } while ( ns_shifrp  -> buf3index < 3 ) ;
      // next letters begins with zero index
      // следующие буквы начинают с нулевого индекса
      ns_shifrp  -> buf3index = 0 ;
      uint16_t u16 = (  ( uint16_t  ) ( ( ns_shifrp  -> buf3 ) [ 0 ] - 'R' ) ) +
        40U * ( ( ( uint16_t  ) ( ( ns_shifrp  -> buf3 ) [ 1 ] - 'R' ) ) +
        40U * ( ( uint16_t  ) ( ( ns_shifrp  -> buf3 ) [ 2 ] - 'R' ) ) ) ;
      buf [ 0 ] = u16 bitand 0xff ;
      buf [ 1 ] = u16 >> 8 ; } // flagtext
    else {
      if ( reads + 1 >= input . s )
        goto Exit ;
      buf [ 0 ] = ( * input_buffer ) ;
      ++  input_buffer  ;
      ++  reads ;
      buf [ 1 ] = ( * input_buffer ) ;
      ++  input_buffer  ;
      ++  reads ; } // flag digit
    uint8_t secretdata  [ 4 ] = { [ 0 ] = buf [ 0 ] bitand  0xf ,
      [ 1 ] = ( buf [ 0 ] >>  4 ) bitand  0xf ,
      [ 2 ] = buf [ 1 ] bitand  0xf ,
      [ 3 ] = ( buf [ 1 ] >>  4 ) bitand  0xf  } ;
    uint8_t decrypteddata [ 4 ] ;
    decrypt_sole ( & secretdata , ( arrcp ) & ( ns_shifrp  -> deshi ) ,
      & decrypteddata , 4 , & ns_shifrp  -> old_last_sole ,
      & ns_shifrp  -> old_last_data ) ;
    ( * output_buffer ) = ( decrypteddata [ 0 ] bitand 0x3  ) bitor
      ( ( decrypteddata [ 1 ] bitand 0x3  ) << 2  )
      bitor ( ( decrypteddata [ 2 ] bitand 0x3  ) <<  4 ) bitor
      ( ( decrypteddata [ 3 ] bitand 0x3  ) << 6  ) ;
    ++  writes  ;
    ++  output_buffer ; }
Exit :
  return  ( size_io ) { .i  = reads , .o  = writes  } ; }

void shifr_decrypt6 ( t_ns_shifr * const ns_shifrp ) {
  uint8_t secretdata [ 1 ] ;
  uint8_t old_last_data = 0 ;
  uint8_t old_last_sole = 0 ;
  while ( not isEOFstreambuf_read6bits ( ns_shifrp , & ns_shifrp -> filebuffrom ,
    & ( secretdata [ 0 ] ) ) ) {
    uint8_t decrypteddata [ 1 ] ;
    decrypt_sole6 ( & secretdata , ( arrcp ) & ns_shifrp  -> deshi6 , & decrypteddata ,
      1 , & old_last_sole , & old_last_data ) ;
    streambuf_write3bits (
      ns_shifrp , & ns_shifrp -> filebufto , decrypteddata [ 0 ] ) ; } }

// inits array [ 0..15 , 0..14 , ... , 0..2 , 0..1 ]
void  shifr_generate_pass4 ( t_ns_shifr * const ns_shifrp ) {
  uint8_t * j = & ( ns_shifrp -> raspr4  . dice [ 0 ] ) ;
  uint8_t i  = 16 ;
  do {
    ( * j ) = rand  ( ) % i ;
    -- i  ;
    ++ j  ;
  } while ( i >= 2 ) ; }

// inits array [ 0..63 , 0..62 , ... , 0..2 , 0..1 ]
void  shifr_generate_pass6 ( t_ns_shifr * const ns_shifrp ) {
  uint8_t * j = & ( ns_shifrp -> raspr6  . dice [ 0 ] ) ;
  uint8_t i  = 64 ;
  do {
    ( * j ) = rand  ( ) % i ;
    -- i  ;
    ++ j  ;
  } while ( i >= 2 ) ; }

// [ 0..15 , 0..14 , 0..13 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ] =
// = x + y * 16 + z * 16 * 15 + ... + u * 16! / 2 / 3 + v * 16! / 2 = 0 .. 16!-1
void  shifr_pass_to_array4 ( t_ns_shifr * const ns_shifrp ) {
  number_set0 ( number_size2 ) ( & ns_shifrp -> raspr4  . pass  ) ;
  number_type ( number_size2 ) mu  ;
  number_set_byte ( number_size2 ) ( & mu , 1 ) ;
  uint8_t in = 0 ;
  do {
    { number_type ( number_size2 ) mux = mu ;
      // re += dice [ in ] * mu ;
      number_mul_byte ( number_size2 ) ( & mux  ,  ns_shifrp -> raspr4  . dice [ in ] ) ;
      number_add  ( number_size2 ) ( & ns_shifrp -> raspr4  . pass , & mux ) ; }
    //$mu *=  16 - $in ;
    number_mul_byte ( number_size2 ) ( & mu , 0x10 - in  ) ;
    ++  in ;
  } while ( in < 0x10 - 1 ) ; }

// [ 0..63 , 0..62 , 0..61 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ] =
// = x + y * 64 + z * 64 * 63 + ... + u * 64! / 2 / 3 + v * 64! / 2 = 0 .. 64!-1
void  shifr_pass_to_array6 ( t_ns_shifr * const ns_shifrp ) {
  number_set0 ( number_size3 ) ( & ns_shifrp -> raspr6  . pass  ) ;
  number_type ( number_size3 ) mu  ;
  number_set_byte ( number_size3 ) ( & mu , 1 ) ;
  uint8_t in = 0 ;
  do {
    { number_type ( number_size3 ) mux = mu ;
      // re += dice [ in ] * mu ;
      number_mul_byte ( number_size3 ) (
        & mux  ,  ns_shifrp -> raspr6  . dice [ in ] ) ;
      number_add  ( number_size3 ) ( & ns_shifrp -> raspr6  . pass , & mux ) ; }
    //$mu *=  64 - $in ;
    number_mul_byte ( number_size3 ) ( & mu , 0x40 - in  ) ;
    ++  in ;
  } while ( in < 0x40 - 1 ) ; }

# ifdef SHIFR_DEBUG

# define  shifr_number_def_princ( N ) \
void  shifr_number##N##_princ ( number_type ( N ) const * const restrict  np ,  \
  FILE * const fs ) { \
  fputs ( "[ " , fs ) ; \
  int8_t i = N ;  \
  do {  \
    -- i ;  \
    fprintf ( fs  , "%x , " , number_elt_copy ( N ) ( np , i ) ) ;  \
  } while ( i ) ; \
  fputs ( "]" , fs ) ; }
# define  number_def_princ shifr_number_def_princ

number_def_princ  ( number_size2 )
number_def_princ  ( number_size3 )

# endif // SHIFR_DEBUG

void  string_to_password ( t_ns_shifr * const ns_shifrp ) {
      switch ( ns_shifrp -> use_version ) {
      case 4 :
        if ( ns_shifrp -> password_alphabet == 95 )
          string_to_password_templ  ( number_size2 ) ( ns_shifrp ,
            ( strcp ) & ns_shifrp  -> password_letters2 ,
            & ns_shifrp -> raspr4  . pass ,
            ( strcp ) & ns_shifrp -> letters ,  letters_count ) ;
        else
          string_to_password_templ  ( number_size2 ) ( ns_shifrp ,
            ( strcp ) & ns_shifrp  -> password_letters2 ,
            & ns_shifrp -> raspr4  . pass ,
            ( strcp ) & ns_shifrp -> letters2 , letters_count2 ) ;
      break ;
      case 3 :
      case 6 : 
        if ( ns_shifrp -> password_alphabet == 95 )
          string_to_password_templ  ( number_size3 ) ( ns_shifrp ,
            ( strcp ) & ns_shifrp  -> password_letters3 ,
            & ns_shifrp -> raspr6  . pass ,
            ( strcp ) & ns_shifrp -> letters ,  letters_count ) ;
        else
          string_to_password_templ  ( number_size3 ) ( ns_shifrp , 
            ( strcp ) & ns_shifrp  -> password_letters3 ,
            & ns_shifrp -> raspr6  . pass ,
            ( strcp ) & ns_shifrp -> letters2 , letters_count2 ) ;
      break ;
      default :
        fprintf ( stderr  , ( ns_shifrp -> localerus ?
          u8"string_to_password : версия %d не поддерживается\n" :
          "string_to_password : version %d is not supported" ) , ns_shifrp -> use_version )  ;
        ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
          ( strcp ) & u8"string_to_password : версия не поддерживается" :
          ( strcp ) & "string_to_password : version is not supported" ) ;
        longjmp ( ns_shifrp  -> jump  , 1 ) ; } }

void  password_load_uni ( t_ns_shifr * const ns_shifrp ) {
  switch ( ns_shifrp -> use_version )  {
  case 4 :
    password_load ( number_size2 ) ( & ns_shifrp -> raspr4  . pass ,
      & ns_shifrp  -> shifr , & ns_shifrp  -> deshi ) ;
    break ;
  case 3 :
  case 6 :
    password_load ( number_size3 ) ( & ns_shifrp -> raspr6  . pass , 
      & ns_shifrp  -> shifr6 , & ns_shifrp  -> deshi6 ) ;
    break ;
  default :
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      u8"password_load:версия %d не поддерживается\n" :
      "password_load:version %d is not supported" ) , ns_shifrp -> use_version )  ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( strcp ) & u8"password_load:версия не поддерживается" :
      ( strcp ) & "password_load:version is not supported" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; } }

void  password_to_string  ( t_ns_shifr * const ns_shifrp ) {
  switch  ( ns_shifrp -> use_version ) {
  case  4 : {
        if ( ns_shifrp -> password_alphabet == 95 )
          password_to_string_templ  ( number_size2 ) ( & ns_shifrp -> raspr4  . pass ,
            & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters ,
            letters_count ) ;
        else
          password_to_string_templ  ( number_size2 ) ( & ns_shifrp -> raspr4  . pass ,
            & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters2 ,
            letters_count2 ) ; 
        break ; }
   case 6 : {
        if ( ns_shifrp -> password_alphabet == 95 )
          password_to_string_templ  ( number_size3 ) ( & ns_shifrp -> raspr6  . pass ,
            & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters ,
            letters_count ) ;
        else
          password_to_string_templ  ( number_size3 ) ( & ns_shifrp -> raspr6  . pass ,
            & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters2 ,
            letters_count2 ) ;
        break ; }
    default :
      fprintf ( stderr  , ( ns_shifrp -> localerus ?
        u8"password_to_string:версия %d не поддерживается\n" :
        "password_to_string:version %d is not supported" ) ,
        ns_shifrp -> use_version )  ;
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( strcp ) & u8"password_to_string:версия не поддерживается" :
        ( strcp ) & "password_to_string:version is not supported" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; } }

