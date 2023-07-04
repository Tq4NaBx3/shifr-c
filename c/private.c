// Shifr ©2020-3 Glebe A.N.
// Шифр ©2020-3 Глебов А.Н.

# include <sys/types.h> // ssize_t
# include "define.h"
# include "struct.h"
# include "cast.h" // int_cast_uint8
# include <iso646.h> // bitor

static  ssize_t shifr_getrandom  ( shifr_arrps )  ;

# define  SHIFR_RANDOM_getrandom
// # define  SHIFR_RANDOM_rand

// ! declare in Makefile USE_GNU_SOURCE = -D'_GNU_SOURCE'
// # define  SHIFR_RANDOM_syscall

# ifdef  SHIFR_RANDOM_rand
# include <stdlib.h> // srand
# include <time.h>
# include <stdbool.h>

static  ssize_t shifr_getrandom  ( shifr_arrps const vec ) {
  static  bool  first = true  ;
  if ( first  ) {
    if  ( sizeof  ( unsigned  int ) ==  4 )
      srand ( lint_cast_ulint ( time  ( 0 ) ) % 0x100000000UL ) ;
    else  if  ( sizeof  ( unsigned  int ) ==  2 )
      srand ( lint_cast_ulint ( time  ( 0 ) ) % 0x10000UL ) ;
    else
      srand ( ulint_cast_uint ( lint_cast_ulint ( time  ( 0 ) ) ) ) ;
    first = false ;
  }
  uint8_t * p = & ( ( * ( vec . p ) ) [ 0 ] ) ;
  size_t j = vec . s ;
  while ( j ) {
    -- j ;
    * p = int_cast_uint8 ( rand  ( ) bitand  0xff ) ;    
    ++ p ;
  }
  return ulint_cast_lint ( vec . s ) ;
}
# else
# ifdef  SHIFR_RANDOM_getrandom
# include <sys/random.h> // getrandom
// OR
// # include <linux/random.h> // getrandom
static  ssize_t shifr_getrandom  ( shifr_arrps const vec ) {
  return getrandom ( vec . p , vec . s , 0 ) ;
}
# else
# ifdef  SHIFR_RANDOM_syscall
# include <unistd.h> // syscall
# include <sys/syscall.h> // SYS_getrandom
static  ssize_t shifr_getrandom  ( shifr_arrps const vec ) {
  return  syscall ( SYS_getrandom , vec . p , vec . s , 0 ) ;
}
# else
# error SHIFR_RANDOM no rand no getrandom no syscall
# endif
# endif
# endif

# include "private.h"

// generate secret random number [ fr .. to ]
void  shifr_uirandfrto  ( struct  s_shifr_fr_to volatile  * const p ) {
# ifdef SHIFR_DEBUG
  if ( p -> fr >= p -> to ) {
    fprintf ( stderr  , "uirandfrto : fr >= to , fr = %u , to = %u\n"  , p -> fr , p -> to ) ;
    p -> sh -> string_exception  = ( shifr_strcp ) & "uirandfrto : fr >= to" ;
    goto exc ;
  }
  if ( p -> fr + 0x100 <= p -> to ) {
    fprintf ( stderr  , "uirandfrto : fr + 0x100 <= to , fr = %u , to = %u\n"  , p -> fr , p -> to ) ;
    p -> sh -> string_exception  = ( shifr_strcp ) & "uirandfrto : fr + 0x100 <= to" ;
    goto exc ;
  }
# endif
  uint8_t bufa  [ 1 ] ;
  shifr_arrps const bufv = { . p = & bufa , . s = 1 } ;
  do {
# ifdef SHIFR_DEBUG
    ssize_t const r = 
# endif
      shifr_getrandom ( bufv ) ;
# ifdef SHIFR_DEBUG
    if ( r == -1 ) {
      perror  ( "uirandfrto : getrandom" ) ;
      p -> sh  -> string_exception  = ( shifr_strcp ) & "uirandfrto : getrandom" ;
      goto exc ;
    }
    if ( r not_eq 1 ) {
      fprintf ( stderr  , "uirandfrto : r = %ld not_eq 1\n"  , r ) ;
      p -> sh  -> string_exception  = ( shifr_strcp ) & "uirandfrto : r not_eq 1" ;
      goto exc ;
    }
# endif // SHIFR_DEBUG
  } while ( bufa [ 0 ] + 0x100 % ( p -> to - p -> fr + 1 ) >= 0x100 ) ;
  p -> res = p -> fr + bufa [ 0 ] % ( p -> to - p -> fr + 1 ) ;
  return  ;
# ifdef SHIFR_DEBUG
exc : ;
  jmp_buf * const j = & ( p ->  sh  ->  jump ) ;
  p ->  sh  = 0 ;
  p ->  fr  = 0 ;
  p ->  to  = 0 ;
  p ->  res = 0 ;
  longjmp ( * j , 1 ) ;
# endif
}

// data_size = 4
void shifr_datasalt ( v2 ) ( t_ns_shifr * const ns_shifrp
# ifndef SHIFR_DEBUG
  __attribute__ ((unused))
# endif
  , shifr_arrcp const secretdata , shifr_arrp const secretdatasalt ,
  size_t const data_size ) {
  uint8_t const * restrict  id = &  ( ( * secretdata  ) [ data_size ] ) ;
  uint8_t * restrict  ids = & ( ( * secretdatasalt  ) [ data_size ] ) ;
  uint8_t rana [ 1 ] ;
  shifr_arrps const ranv = { . p = & rana , . s = 1 } ;
# ifdef SHIFR_DEBUG
  ssize_t const r =
# endif
    shifr_getrandom ( ranv ) ;
# ifdef SHIFR_DEBUG
    if ( r == -1 ) {
      perror  ( "datasalt2 : getrandom" ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp )
        & "datasalt2 : getrandom" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ;
    }
    if ( r not_eq 1 ) {
      fprintf ( stderr  , "datasalt2 : r = %ld not_eq 1\n"  , r ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp )
        & "datasalt2 : r not_eq 1" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ;
    }
# endif // SHIFR_DEBUG
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 10 =>
    //   10_00 или 10_01 или 10_10 или 10_11
    // в таблице всё рядом, 4 варианта равномерно распределены
    // the main thing is data , the tail is salt : 10 =>
    //   10_00 or 10_01 or 10_10 or 10_11
    // in the table, everything is side by side, 4 options are evenly
    // distributed
    ( * ids ) = int_cast_uint8 ( ( ( * id  ) <<  2 ) bitor ( rana [ 0 ] bitand  0x3 ) ) ;
    rana [ 0 ] >>= 2 ;
  } while ( id not_eq & ( ( * secretdata  ) [ 0 ] ) ) ;
}

// data_size = 1 .. 3
void shifr_datasalt ( v3 ) ( t_ns_shifr * const ns_shifrp
# ifndef SHIFR_DEBUG
  __attribute__ ((unused))
# endif
  , shifr_arrcp const secretdata , shifr_arrp const secretdatasalt ,
  size_t const data_size ) {
  uint8_t const * restrict  id = &  ( ( * secretdata  ) [ data_size ] ) ;
  uint8_t * restrict  ids = & ( ( * secretdatasalt  ) [ data_size ] ) ;
  unsigned  int const arans = ( ( data_size == 3U ) ? 2U : 1U ) ;
  uint8_t aran [ arans ] ;
  shifr_arrps const aranv = { . p = & aran , . s = arans } ;
# ifdef SHIFR_DEBUG
  ssize_t const r =
# endif
    shifr_getrandom ( aranv ) ;
# ifdef SHIFR_DEBUG
  if ( r == -1 ) {
    perror  ( "datasalt3 : getrandom" ) ;
    ns_shifrp  -> string_exception  = ( shifr_strcp )
      & "datasalt3 : getrandom" ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
  if ( r not_eq arans ) {
    fprintf ( stderr  , "datasalt3 : r = %ld not_eq %d\n"  , r , arans ) ;
    ns_shifrp  -> string_exception  = ( shifr_strcp ) 
      & "datasalt3 : r not_eq arans" ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
# endif // SHIFR_DEBUG
  unsigned  int ran = aran [ 0 ] ;
  if ( arans == 2 )
    ran |=  ( ( uint8_cast_uint ( aran [ 1 ] ) ) << 8 ) ;
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 101 =>
    //   101_000 или 101_001 или ... или 101_111
    // в таблице всё рядом, 8 вариантов равномерно распределены
    // the main thing is data , the tail is salt : 101 =>
    //   101_000 or 101_001 or ... or 101_111
    // in the table, everything is side by side, 8 options are evenly
    // distributed
    ( * ids ) = uint_cast_uint8 (
      ( int_cast_uint ( ( * id  ) <<  3 ) ) bitor
      ( ran bitand  0x7 ) ) ;
    ran >>= 3 ;
  } while ( id not_eq & ( ( * secretdata  ) [ 0 ] ) ) ;
}

// пишу по шесть бит
// secretdatasaltsize - количество шести-битных отделов (2 или 3)
// encrypteddata - массив шести-битных чисел
// I write in six bits
// secretdatasaltsize - the number of six-bit divisions (2 or 3)
// encrypteddata - array of six-bit numbers

void  shifr_streambuf_write3 ( t_shifr_streambuf_write3 const arg ) {
  if  ( arg . ns_shifrp  -> flagtext  )
    goto  FlagText  ;
  else
    goto  NotFlagText ;
FlagText  :
  { uint8_t i = 0 ;
    do {
      char  const buf2  = shifr_bits6_to_letter (
# ifdef SHIFR_DEBUG
        arg . ns_shifrp ,
# endif
        ( * arg . encrypteddata ) [ i ] ) ;
      if ( ( * arg . writesp ) >= arg . outputs ) {
        arg . ns_shifrp  -> string_exception  = ( arg . ns_shifrp  -> localerus ?
          ( shifr_strcp ) & "streambuf_write3: переполнение буфера (flagtext)"  :
          ( shifr_strcp ) & "streambuf_write3: buffer overflow (flagtext)" ) ;
        longjmp ( arg . ns_shifrp  -> jump  , 1 ) ;
      }
      ( * * arg . output_bufferp ) = char_cast_uint8 ( buf2 ) ;
      ++  ( * arg . output_bufferp )  ;
      ++  ( * arg . writesp ) ;
      ++  ( arg . ns_shifrp ->  bytecountw  ) ;
      if  ( ( arg . ns_shifrp ->  bytecountw  ) >=  60  ) {
        if ( ( * arg . writesp ) >= arg . outputs ) {
          arg . ns_shifrp  -> string_exception  = ( arg . ns_shifrp  -> localerus ?
            ( shifr_strcp ) & "streambuf_write3: переполнение буфера для '\\n'"  :
            ( shifr_strcp ) & "streambuf_write3: buffer overflow for '\\n'" ) ;
          longjmp ( arg . ns_shifrp  -> jump  , 1 ) ;
        }
        ( * * arg . output_bufferp ) = '\n' ;
        ++  ( * arg . output_bufferp )  ;
        ++  ( * arg . writesp ) ;
        arg . ns_shifrp ->  bytecountw  = 0 ;
      }
      ++  i ;
    } while ( i < arg . secretdatasaltsize ) ;
  }
  return  ;
NotFlagText :
  { uint8_t i = 0 ;
    shifr_t_streambuf * const me = & arg . ns_shifrp -> filebufto ;
    do {
      if  ( ( me -> bufbitsize ) < 2 ) {
        me -> buf = ( me -> buf ) bitor
          int_cast_uint8 ( ( ( * arg . encrypteddata ) [ i ] ) << ( me -> bufbitsize ) ) ;
        me -> bufbitsize = int_cast_uint8 ( ( me -> bufbitsize ) + 6 ) ;
      } else  {
        uint8_t const to_write  = int_cast_uint8 ( ( ( ( * arg . encrypteddata ) [ i ]
          ) << ( me -> bufbitsize  ) ) bitor ( me -> buf ) ) ;
        if ( ( * arg . writesp ) >= arg . outputs ) {
          arg . ns_shifrp  -> string_exception  = ( arg . ns_shifrp  -> localerus ?
            ( shifr_strcp ) & "streambuf_write3: переполнение буфера (flagdigit)"  :
            ( shifr_strcp ) & "streambuf_write3: buffer overflow (flagdigit)" ) ;
          longjmp ( arg . ns_shifrp  -> jump  , 1 ) ;
        }
        ( * * arg . output_bufferp ) = to_write ;
        ++  ( * arg . output_bufferp )  ;
        ++  ( * arg . writesp ) ;
        // + 6 - 8
        me -> bufbitsize = uint_cast_uint8 ( ( me -> bufbitsize ) - 2U ) ;
        me -> buf = int_cast_uint8 ( ( ( * arg . encrypteddata ) [ i ] ) >>
          ( 6 - ( me -> bufbitsize ) ) ) ;
      }
      ++  i ;
    } while ( i < arg . secretdatasaltsize ) ;
  }
  return  ;
}

// версия 3 пишу три бита для расшифровки
// version 3 write three bits to decode
void  shifr_streambuf_write3bits ( t_ns_shifr * const ns_shifrp ,
  uint8_t const encrypteddata , uint8_t * restrict * const output_bufferp ,
  size_t * const writesp ) {
  shifr_t_streambuf * const restrict me  = & ns_shifrp -> filebufto  ;
  if  ( ( me -> bufbitsize ) < 5 ) {
    me -> buf = int_cast_uint8 ( ( me -> buf ) bitor
      ( encrypteddata <<  ( me -> bufbitsize ) ) ) ;
    me -> bufbitsize = uint_cast_uint8 ( ( me -> bufbitsize ) + 3U ) ;
  } else  {
    uint8_t const to_write  = int_cast_uint8 ( ( encrypteddata   << (
      me -> bufbitsize ) ) bitor ( me -> buf ) ) ;
    ( * * output_bufferp ) = to_write  ;
    ++  ( * output_bufferp  ) ;
    ++  ( * writesp ) ;
    // + 3 - 8
    me -> bufbitsize = uint_cast_uint8 ( ( me -> bufbitsize ) - 5U ) ;
    me -> buf = int_cast_uint8 ( encrypteddata   >>
      ( 3 - ( me -> bufbitsize ) ) ) ;
  }
}     

// from stdin get password string -> make big number
//  + create tables shifr deshi

# define  shifr_enter_password_templ( funname , ver , rasprname ) \
void  funname ( t_ns_shifr * const ns_shifrp ) { \
  char  volatile  p40 [ shifr_password_letters_size ( ver ) ] ; \
  shifr_set_keypress  ( ns_shifrp ) ; \
  if ( ! fgets ( ( char  * ) & ( p40 [ 0 ] ) , shifr_password_letters_size ( ver ) , stdin ) ) { \
    shifr_memsetv ( p40 , shifr_memsetv_default_byte , sizeof  ( p40 ) ) ; \
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? \
      ( shifr_strcp ) & # funname " : ошибка чтения входящего потока" : \
      ( shifr_strcp ) & # funname " : error reading input stream" ) ; \
    longjmp ( ns_shifrp  -> jump  , 1 ) ; \
  } \
  shifr_reset_keypress ( ns_shifrp ) ; \
  { char volatile * j = & ( p40 [ 0 ] ) ; \
    while ( ( ( * j ) not_eq '\n' ) and ( ( * j ) not_eq '\00' ) and \
      ( j < ( & ( p40 [ shifr_password_letters_size ( ver ) ] ) ) ) ) \
      ++ j ; \
    if ( j < ( & ( p40 [ shifr_password_letters_size ( ver ) ] ) ) ) \
      ( * j ) = '\00' ; \
    else  { \
      shifr_memsetv ( p40 , shifr_memsetv_default_byte , sizeof  ( p40 ) ) ; \
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? \
        ( shifr_strcp ) & # funname " : в пароле нет конца строки" : \
        ( shifr_strcp ) & # funname " : there is no end of line in the password" ) ; \
      longjmp ( ns_shifrp  -> jump  , 1 ) ; \
    } \
  } \
  switch ( ns_shifrp -> password_alphabet ) { \
  case  shifr_letters_count  : \
    shifr_string_to_password_templ  ( ver ) ( ns_shifrp , \
      ( shifr_strvcp ) & p40 , & ns_shifrp -> rasprname  . pass . pub , \
      ( shifr_strcp ) & ns_shifrp -> letters , shifr_letters_count ) ; \
    break ; \
  case  shifr_letters_count62  : \
    shifr_string_to_password_templ  ( ver ) ( ns_shifrp , \
      ( shifr_strvcp ) & p40 , & ns_shifrp -> rasprname  . pass . pub , \
      ( shifr_strcp ) & ns_shifrp -> letters62 , shifr_letters_count62 ) ; \
    break ; \
  case  shifr_letters_count52  : \
    shifr_string_to_password_templ  ( ver ) ( ns_shifrp , \
      ( shifr_strvcp ) & p40 , & ns_shifrp -> rasprname  . pass . pub , \
      ( shifr_strcp ) & ns_shifrp -> letters52 , shifr_letters_count52 ) ; \
    break ; \
  case  shifr_letters_count_Digit  : \
    shifr_string_to_password_templ  ( ver ) ( ns_shifrp , \
      ( shifr_strvcp ) & p40 , & ns_shifrp -> rasprname  . pass . pub , \
      ( shifr_strcp ) & ns_shifrp -> letters_Digit , shifr_letters_count_Digit ) ; \
    break ; \
  case  shifr_letters_count4  : \
    shifr_string_to_password_templ  ( ver ) ( ns_shifrp , \
      ( shifr_strvcp ) & p40 , & ns_shifrp -> rasprname  . pass . pub , \
      ( shifr_strcp ) & ns_shifrp -> letters4 , shifr_letters_count4 ) ; \
    break ; \
  default : \
    shifr_memsetv ( p40 , shifr_memsetv_default_byte , sizeof  ( p40 ) ) ; \
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? \
      ( shifr_strcp ) & # funname " : неизвестный алфавит пароля" : \
      ( shifr_strcp ) & # funname " : unknown password alphabet" ) ; \
    longjmp ( ns_shifrp  -> jump  , 1 ) ; \
  } \
  char  volatile  password_letters [ shifr_password_letters_size ( ver ) ] ; \
  switch  ( ns_shifrp -> password_alphabet  ) { \
  case  shifr_letters_count : \
    shifr_password_to_string_templ  ( ver ) ( \
      & ns_shifrp -> rasprname  . pass . pub , & password_letters , \
      & ns_shifrp -> letters , shifr_letters_count ) ; \
    break ; \
  case  shifr_letters_count62  : \
    shifr_password_to_string_templ  ( ver ) ( \
      & ns_shifrp -> rasprname  . pass . pub , & password_letters , \
      & ns_shifrp -> letters62 , shifr_letters_count62 ) ; \
    break ; \
  case  shifr_letters_count52  : \
    shifr_password_to_string_templ  ( ver ) ( \
      & ns_shifrp -> rasprname  . pass . pub , & password_letters , \
      & ns_shifrp -> letters52 , shifr_letters_count52 ) ; \
    break ; \
  case  shifr_letters_count_Digit  : \
    shifr_password_to_string_templ  ( ver ) ( \
      & ns_shifrp -> rasprname  . pass . pub , & password_letters , \
      & ns_shifrp -> letters_Digit , shifr_letters_count_Digit ) ; \
    break ; \
  case  shifr_letters_count4  : \
    shifr_password_to_string_templ  ( ver ) ( \
      & ns_shifrp -> rasprname  . pass . pub , & password_letters , \
      & ns_shifrp -> letters4 , shifr_letters_count4 ) ; \
    break ; \
  default : \
    shifr_memsetv ( p40 , shifr_memsetv_default_byte , sizeof  ( p40 ) ) ; \
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? \
      ( shifr_strcp ) & # funname " : неизвестный алфавит пароля" : \
      ( shifr_strcp ) & # funname " : unknown password alphabet" ) ; \
    longjmp ( ns_shifrp  -> jump  , 1 ) ; \
  } \
  if  ( strcmp ( ( char * ) & ( password_letters  [ 0 ] ) , \
    ( char * ) & ( p40 [ 0 ] ) ) ) \
    fprintf  ( stderr , ( ns_shifrp -> localerus ? \
      # funname " : Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" : \
      # funname " : Warning! Password \'%s\' is very large. Same as \'%s\'\n" ) \
      , & ( p40 [ 0 ] ) , & ( password_letters [ 0 ] ) ) ; \
  shifr_memsetv ( p40 , shifr_memsetv_default_byte , sizeof  ( p40 ) ) ; \
  shifr_memsetv ( password_letters  , shifr_memsetv_default_byte , \
    sizeof  ( password_letters  ) ) ; \
}

# include <string.h> // strcmp

shifr_enter_password_templ  ( shifr_enter_password_name  ( v2  ) , v2 , raspr2 )
shifr_enter_password_templ  ( shifr_enter_password_name  ( v3  ) , v3 , raspr3 )

// читаю 6 бит
// 6 bits reads

// ! to do : arguments as struct

bool  isEOBstreambuf_read6bits ( t_ns_shifr * const ns_shifrp ,
  uint8_t * const encrypteddata , size_t * const  readsp ,
  uint8_t const * restrict * const input_bufferp , size_t const inputs ) {
  shifr_t_streambuf * const restrict me = & ns_shifrp -> filebuffrom ;
  if  ( ns_shifrp  -> flagtext  ) {
    uint8_t buf ;
    do  {
      if ( ( * readsp ) >= inputs )
        return  true  ;
      buf = * * input_bufferp  ;
      ++  ( * input_bufferp  ) ;
      ++  ( * readsp ) ;
      // читаем одну букву Base64 -> декодируем в шесть бит
      // reads one letter Base64 -> decode to six bits
    } while ( ( buf not_eq char_cast_uint8 ( '+' ) ) and
      ( ( buf < char_cast_uint8 ( '/' ) ) or ( buf > char_cast_uint8 ( '9' ) ) ) and
      ( ( buf < char_cast_uint8 ( 'A' ) ) or ( buf > char_cast_uint8 ( 'Z' ) ) ) and
      ( ( buf < char_cast_uint8 ( 'a' ) ) or ( buf > char_cast_uint8 ( 'z' ) ) ) ) ;
    ( * encrypteddata ) = shifr_letter_to_bits6 (
# ifdef SHIFR_DEBUG
      ns_shifrp ,
# endif
      uint8_cast_char ( buf ) ) ;
    return  false ;
  }
  if  ( ( me -> bufbitsize ) >= 6 ) {
    me -> bufbitsize = uint_cast_uint8 ( ( me -> bufbitsize ) - 6U ) ;
    ( * encrypteddata ) = ( me -> buf ) bitand ( 0x40 - 1 ) ;
    ( me -> buf ) >>= 6 ;
    return  false ;
  }
  uint8_t buf = * * input_bufferp  ;
  ++  ( * readsp ) ;
  ++  ( * input_bufferp  ) ;
  ( * encrypteddata ) = ( ( me -> buf ) bitor
    ( buf <<  ( me -> bufbitsize ) ) ) bitand ( 0x40 - 1 )  ;
  me -> buf = int_cast_uint8 ( buf >> ( 6 - ( me -> bufbitsize ) ) ) ;
  // + 8 - 6
  me -> bufbitsize = int_cast_uint8 ( ( me -> bufbitsize ) + 2 ) ;
  return  false ;
}

void  shifr_decrypt_salt ( v2 ) ( shifr_arrp const datap ,
  shifr_arrvcp  const tablep , shifr_arrp const decrp , size_t const data_size  ,
  uint8_t * const restrict old_last_salt , uint8_t * const restrict old_last_data ) {
  uint8_t const * restrict  id = & ( ( * datap ) [ 0 ] ) ;
  uint8_t * restrict  ide = & ( ( * decrp ) [ 0 ] ) ;
  do {
    { uint8_t const data_salt = ( * tablep ) [ * id ] ;
      ( * ide ) = ( data_salt >>  2 ) xor ( * old_last_salt ) ;
      ( * old_last_salt ) = int_cast_uint8 (
        (  data_salt bitand  0x3 ) xor ( * old_last_data ) ) ;
    }
    ( * old_last_data ) = ( * ide ) ;
    ++  id  ;
    ++  ide ;
  } while ( id not_eq & ( ( * datap ) [ data_size ] ) ) ;
}

void  shifr_decrypt_salt ( v3 ) ( shifr_arrp const datap ,
  shifr_arrvcp  const tablep , shifr_arrp const decrp , size_t const data_size ,
  uint8_t * const restrict old_last_salt , uint8_t * const restrict old_last_data ) {
  uint8_t const * restrict  id = & ( ( * datap ) [ 0 ] ) ;
  uint8_t * restrict  ide = & ( ( * decrp ) [ 0 ] ) ;
  do {
    { uint8_t const data_salt = ( * tablep ) [ * id ] ;
      ( * ide ) = ( data_salt >>  3 ) xor ( * old_last_salt ) ;
      ( * old_last_salt ) = int_cast_uint8 (
        ( data_salt bitand  0x7 ) xor ( * old_last_data ) ) ;
      ( * old_last_data ) = ( * ide ) ;
    }
    ++  id  ;
    ++  ide ;
  } while ( id not_eq & ( ( * datap ) [ data_size ] ) ) ;
}

void  shifr_data_xor2  ( t_ns_shifr * const ns_shifrp ,
  shifr_arrp  const secretdatasalt  , size_t  const data_size ) {
  uint8_t * restrict  ids = & ( ( * secretdatasalt  ) [ 0 ] ) ;
  do {
    uint8_t const cur_data  = ( * ids ) >> 2 ;
    uint8_t const cur_salt  = ( * ids ) bitand  0x3 ;
    // главное данные , хвост - соль : 01 =>
    //   01_00 или 01_01 или 01_10 или 01_11
    // в таблице всё рядом, 4 варианта равномерно распределены
    // данные сыпью предыдущей солью
    // the main thing is data , the tail is salt : 01 =>
    //   01_00 or 01_01 or 01_10 or 01_11
    // in the table, everything is side by side, 4 options are evenly
    // distributed the data is a rash of the previous salt
    ( * ids ) = int_cast_uint8 ( ( * ids ) xor ( ( ns_shifrp -> old_last_salt )
        << 2  ) ) ;
    ( * ids ) xor_eq  ( ns_shifrp -> old_last_data ) ;
    // беру свежую соль
    // I take fresh salt
    ns_shifrp ->  old_last_salt = cur_salt  ;
    ns_shifrp ->  old_last_data = cur_data  ;
    ++  ids ;
  } while ( ids not_eq & ( ( * secretdatasalt ) [ data_size ] ) ) ;
}

void  shifr_crypt_decrypt ( shifr_arrp const datap ,
  shifr_arrvcp  const tablep , shifr_arrp const encrp , size_t const data_size ) {
  uint8_t const * id = & ( ( * datap ) [ data_size ] ) ;
  uint8_t * ied = & ( ( * encrp ) [ data_size ] ) ;
  do {
    -- id ;
    --  ied ;
    ( * ied ) = ( * tablep ) [ * id ] ;
  } while ( id not_eq & ( ( * datap ) [ 0 ] ) ) ;
}

void  shifr_data_xor3 ( uint8_t * const restrict  old_last_data ,
  uint8_t * const restrict  old_last_salt , shifr_arrp  const secretdatasalt  , size_t  const data_size ) {
  uint8_t * restrict  ids = & ( ( * secretdatasalt  ) [ 0 ] ) ;
  do {
    uint8_t const cur_data = ( * ids ) >> 3 ;
    uint8_t const cur_salt = ( * ids ) bitand 0x7 ;
    // главное данные , хвост - соль : 101 =>
    //   101_000 или 101_001 или ... или 101_111
    // в таблице всё рядом, 8 вариантов равномерно распределены
    // данные сыпью предыдущей солью
    // the main thing is data , the tail is salt : 101 =>
    //   101_000 or 101_001 or ... or 101_111
    // in the table, everything is side by side, 8 options are evenly
    // distributed the data is a rash of the previous salt
    ( * ids ) = int_cast_uint8 ( ( * ids ) xor ( ( * old_last_salt ) << 3  ) ) ;
    ( * ids ) xor_eq  ( * old_last_data ) ;
    // берю свежую соль
    // I take fresh salt
    ( * old_last_salt ) = cur_salt ;
    ( * old_last_data ) = cur_data ;
    ++  ids ;
  } while ( ids not_eq & ( ( * secretdatasalt ) [ data_size ] ) ) ;
}

# ifdef SHIFR_DEBUG
uint8_t shifr_letter_to_bits6 ( t_ns_shifr * const ns_shifrp , char  const letter  ) {
  uint8_t const lette = char_cast_uint8 ( letter ) ;
  if ( ( lette not_eq char_cast_uint8 ( '+' ) ) and
      ( ( lette < char_cast_uint8 ( '/' ) ) or ( lette > char_cast_uint8 ( '9' ) ) ) and
      ( ( lette < char_cast_uint8 ( 'A' ) ) or ( lette > char_cast_uint8 ( 'Z' ) ) ) and
      ( ( lette < char_cast_uint8 ( 'a' ) ) or ( lette > char_cast_uint8 ( 'z' ) ) ) ) {
    fprintf ( stderr , "shifr_letter_to_bits6:letter = '%c' [%hhu]\n" , letter , lette ) ;
    fflush ( stderr ) ;
    ns_shifrp  -> string_exception  = ( shifr_strcp ) & "shifr_letter_to_bits6:letter not in Base64" ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
  return  uint_cast_uint8 ( shifr_base64_let_to_num [ char_cast_uint8 ( letter ) - char_cast_uint8 ( '+' ) ] ) ;
}

char  shifr_bits6_to_letter ( t_ns_shifr * const ns_shifrp , uint8_t const bits6 ) {
  if ( bits6 >= 0x40 ) {
    fprintf ( stderr , "shifr_bits6_to_letter:bits6 = '%c' [%hhu]\n" , uint8_cast_char ( bits6 ) , bits6 ) ;
    fflush ( stderr ) ;
    ns_shifrp  -> string_exception  = ( shifr_strcp ) & "shifr_bits6_to_letter:bits6 >= 0x40" ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
  return  int_cast_char ( shifr_base64_num_to_let [ bits6 ] ) ;
}
# endif

char  const shifr_base64_num_to_let [ 0x40  ] = {
  [ 0x00  ] = 'A' , [ 0x01  ] = 'B' , [ 0x02  ] = 'C' , [ 0x03  ] = 'D' , [ 0x04  ] = 'E' , [ 0x05  ] = 'F' ,
  [ 0x06  ] = 'G' , [ 0x07  ] = 'H' , [ 0x08  ] = 'I' , [ 0x09  ] = 'J' , [ 0x0a  ] = 'K' , [ 0x0b  ] = 'L' ,
  [ 0x0c  ] = 'M' , [ 0x0d  ] = 'N' , [ 0x0e  ] = 'O' , [ 0x0f  ] = 'P' , [ 0x10  ] = 'Q' , [ 0x11  ] = 'R' ,
  [ 0x12  ] = 'S' , [ 0x13  ] = 'T' , [ 0x14  ] = 'U' , [ 0x15  ] = 'V' , [ 0x16  ] = 'W' , [ 0x17  ] = 'X' ,
  [ 0x18  ] = 'Y' , [ 0x19  ] = 'Z' , [ 0x1a  ] = 'a' , [ 0x1b  ] = 'b' , [ 0x1c  ] = 'c' , [ 0x1d  ] = 'd' ,
  [ 0x1e  ] = 'e' , [ 0x1f  ] = 'f' , [ 0x20  ] = 'g' , [ 0x21  ] = 'h' , [ 0x22  ] = 'i' , [ 0x23  ] = 'j' ,
  [ 0x24  ] = 'k' , [ 0x25  ] = 'l' , [ 0x26  ] = 'm' , [ 0x27  ] = 'n' , [ 0x28  ] = 'o' , [ 0x29  ] = 'p' ,
  [ 0x2a  ] = 'q' , [ 0x2b  ] = 'r' , [ 0x2c  ] = 's' , [ 0x2d  ] = 't' , [ 0x2e  ] = 'u' , [ 0x2f  ] = 'v' ,
  [ 0x30  ] = 'w' , [ 0x31  ] = 'x' , [ 0x32  ] = 'y' , [ 0x33  ] = 'z' , [ 0x34  ] = '0' , [ 0x35  ] = '1' ,
  [ 0x36  ] = '2' , [ 0x37  ] = '3' , [ 0x38  ] = '4' , [ 0x39  ] = '5' , [ 0x3a  ] = '6' , [ 0x3b  ] = '7' ,
  [ 0x3c  ] = '8' , [ 0x3d  ] = '9' , [ 0x3e  ] = '+' , [ 0x3f  ] = '/' ,
} ;

unsigned  int const shifr_base64_let_to_num [ ] = {
  [ 'A' - '+' ] = 0x00  , [ 'B' - '+' ] = 0x01  , [ 'C' - '+' ] = 0x02  , [ 'D' - '+' ] = 0x03  ,
  [ 'E' - '+' ] = 0x04  , [ 'F' - '+' ] = 0x05  , [ 'G' - '+' ] = 0x06  , [ 'H' - '+' ] = 0x07  ,
  [ 'I' - '+' ] = 0x08  , [ 'J' - '+' ] = 0x09  , [ 'K' - '+' ] = 0x0a  , [ 'L' - '+' ] = 0x0b  ,
  [ 'M' - '+' ] = 0x0c  , [ 'N' - '+' ] = 0x0d  , [ 'O' - '+' ] = 0x0e  , [ 'P' - '+' ] = 0x0f  ,
  [ 'Q' - '+' ] = 0x10  , [ 'R' - '+' ] = 0x11  , [ 'S' - '+' ] = 0x12  , [ 'T' - '+' ] = 0x13  ,
  [ 'U' - '+' ] = 0x14  , [ 'V' - '+' ] = 0x15  , [ 'W' - '+' ] = 0x16  , [ 'X' - '+' ] = 0x17  ,
  [ 'Y' - '+' ] = 0x18  , [ 'Z' - '+' ] = 0x19  , [ 'a' - '+' ] = 0x1a  , [ 'b' - '+' ] = 0x1b  ,
  [ 'c' - '+' ] = 0x1c  , [ 'd' - '+' ] = 0x1d  , [ 'e' - '+' ] = 0x1e  , [ 'f' - '+' ] = 0x1f  ,
  [ 'g' - '+' ] = 0x20  , [ 'h' - '+' ] = 0x21  , [ 'i' - '+' ] = 0x22  , [ 'j' - '+' ] = 0x23  ,
  [ 'k' - '+' ] = 0x24  , [ 'l' - '+' ] = 0x25  , [ 'm' - '+' ] = 0x26  , [ 'n' - '+' ] = 0x27  ,
  [ 'o' - '+' ] = 0x28  , [ 'p' - '+' ] = 0x29  , [ 'q' - '+' ] = 0x2a  , [ 'r' - '+' ] = 0x2b  ,
  [ 's' - '+' ] = 0x2c  , [ 't' - '+' ] = 0x2d  , [ 'u' - '+' ] = 0x2e  , [ 'v' - '+' ] = 0x2f  ,
  [ 'w' - '+' ] = 0x30  , [ 'x' - '+' ] = 0x31  , [ 'y' - '+' ] = 0x32  , [ 'z' - '+' ] = 0x33  ,
  [ '0' - '+' ] = 0x34  , [ '1' - '+' ] = 0x35  , [ '2' - '+' ] = 0x36  , [ '3' - '+' ] = 0x37  ,
  [ '4' - '+' ] = 0x38  , [ '5' - '+' ] = 0x39  , [ '6' - '+' ] = 0x3a  , [ '7' - '+' ] = 0x3b  ,
  [ '8' - '+' ] = 0x3c  , [ '9' - '+' ] = 0x3d  , [ '+' - '+' ] = 0x3e  , [ '/' - '+' ] = 0x3f  ,
} ;
# include "inlinepri.h"
