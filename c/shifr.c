// Shifr ©2020-3 Glebe A.N.
// Шифр ©2020-3 Глебов А.Н.

// Version 2

// RUS
// 2 бита соль
// 2 бита инфа
// итого 4 бита
// таблица шифра: личные 2 бита + соль 2 бита => 4 бита шифрованные
// личные данные b00 => могут быть зашифрованы упорядоченным набором
// 2^2 = 4шт из 
// b0000 ... b1111 2^4 = 4*4 = 16 штук
// разные расклады шифрования для данных
// b00 = 16*15*14*13 = 43680
// b01 = 12*11*10*9 = 11880
// b10 = 8*7*6*5 = 1680
// b11 = 4*3*2*1 = 24
// в общем = b00 * b01 * b10 * b11 =
//   = 16! = 20922789888000
// минимум можно записать пароль с помощью
// log(2,20922789888000) ≈ 44.25 бит <= 6 байт
// пароль будет 45 бит
// ascii буквы 126-32+1 = 95 шт
// длина буквенного пароля : log ( 95 , 20922789888000 ) ≈ 6.735 букв <= 7 букв
//  log ( 62 , 20922789888000 ) ≈ 7.432 буквы <= 8 букв
//  log ( 26 , 20922789888000 ) ≈ 9.414 буквы <= 10 букв
//  log ( 10 , 20922789888000 ) ≈ 13.32 цифр <= 14 цифр

/*
OrigData   : 01 11 11
RandomSalt : 10 11 10

Data 01---\/---10⊻11=01---\/---11⊻11=00
Salt 10___/\___01⊻11=10___/\___11⊻10=01  
Pair 0110      0110            0001
Secr xxxx      xxxx            yyyy

Соль одного элемента будет ксорить следующий элемент для исчезания повторов.
Данные первого элемента будут ксорить соль второго элемента.
Если все элементы будут одного значения, тогда все
 шифрованные значения будут иметь свойство псевдо-случайности.
И данные и соль имеют секретность кроме первой нулевой соли.
Функция Шифр(пары: данные+соль) должна быть случайной неупорядоченной.

*/

// ENG
// 2 bits salt
// 2 bits information
// total 4 bits
// encryption table: personal 2 bits + salt 2 bits => 4 bits encrypted
// personal data b00 => can be encrypted in an ordered set 2^2 = 4pcs from
// b0000 ... b1111 2^4 = 4*4 = 16 pieces
// different encryption layouts for data
// b00 = 16*15*14*13 = 43680
// b01 = 12*11*10*9 = 11880
// b10 = 8*7*6*5 = 1680
// b11 = 4*3*2*1 = 24
// generally = b00 * b01 * b10 * b11 =
//   = 16! = 20922789888000
// minimum you can write a password using
// log(2,20922789888000) ≈ 44.25 bits <= 6 bytes
// the password will have 45 bits size
// ascii letters 126-32+1 = 95 pcs
// letter password length : log ( 95 , 20922789888000 ) ≈ 6.735 letters
// <= 7 letters
//  log ( 62 , 20922789888000 ) ≈ 7.432 letters <= 8 letters
//  log ( 26 , 20922789888000 ) ≈ 9.414 letters <= 10 letters
//  log ( 10 , 20922789888000 ) ≈ 13.32 digits <= 14 digits

/*
OrigData   : 01 11 11
RandomSalt : 10 11 10

Data 01---\/---10⊻11=01---\/---11⊻11=00
Salt 10___/\___01⊻11=10___/\___11⊻10=01  
Pair 0110      0110            0001
Secr xxxx      xxxx            yyyy

The salt of one element will modify (xor) the next element to remove repeats.
The data of the first element will modify (xor) the second element salt.
If all elements are of the same value, then all encrypted 
 values will have the property of pseudo-randomness.
Both data and salt have secrecy apart from the first zero salt.
Function Shifr(of pair: data+salt)should be randomly disordered.

*/

// Version 3

// RUS
// 3 бита соль
// 3 бита инфа
// итого 6 бит
// таблица шифра: личные 3 бита + соль 3 бита => 6 бита шифрованные
// личные данные b000 => могут быть зашифрованы упорядоченным набором 
// 2^3 = 8шт из 
// b000000 ... b111111 2^6 = 8*8 = 64 штук
// разные расклады шифрования для данных
// b000 = 64*63*62*61*60*59*58*57 = 178462987637760
// b001 = 56*55*54*53*52*51*50*49 = 57274321104000
// b010 = 48*47*46*45*44*43*42*41 = 15214711438080
// b011 = 40*39*38*37*36*35*34*33 = 3100796899200
// b100 = 32*31*30*29*28*27*26*25 = 424097856000
// b101 = 24*23*22*21*20*19*18*17 = 29654190720
// b110 = 16*15*14*13*12*11*10*9  = 518918400
// b111 = 8*7*6*5*4*3*2*1         = 40320
// в общем = b000 * b001 * b010 * b011 * b100 * b101 * b110 * b111 = 64! =
// 1268869321858841641034333893351614808028655161745451921988018943752147042304e14
// ≈ 1.26886932186e89
// минимум можно записать пароль с помощью
// log(2,1.26886932186e89) ≈ 296 bits <= 37 bytes
// пароль будет 296 бит
// ascii буквы 126-32+1 = 95 шт
// длина буквенного пароля : log ( 95 , 1.26886932186e89 ) ≈ 45.05 букв 
// <= 46 букв
//  log ( 62 , 1.26886932186e89 ) ≈ 49.71 буквы <= 50 букв
//  log ( 26 , 1.26886932186e89 ) ≈ 62.97 буквы <= 63 буквы
//  log ( 10 , 1.26886932186e89 ) ≈ 89.1 цифр <= 90 цифр

// ENG
// 3 bits salt
// 3 bits information
// total 6 bits
// encryption table: personal 3 bits + salt 3 bits => 6 bits encrypted
// personal data b000 => can be encrypted in an ordered set 2^3 = 8pcs from
// b000000 ... b111111 2^6 = 8*8 = 64 pieces
// different encryption layouts for data
// b000 = 64*63*62*61*60*59*58*57 = 178462987637760
// b001 = 56*55*54*53*52*51*50*49 = 57274321104000
// b010 = 48*47*46*45*44*43*42*41 = 15214711438080
// b011 = 40*39*38*37*36*35*34*33 = 3100796899200
// b100 = 32*31*30*29*28*27*26*25 = 424097856000
// b101 = 24*23*22*21*20*19*18*17 = 29654190720
// b110 = 16*15*14*13*12*11*10*9  = 518918400
// b111 = 8*7*6*5*4*3*2*1         = 40320
// в общем = b000 * b001 * b010 * b011 * b100 * b101 * b110 * b111 = 64! =
// 1268869321858841641034333893351614808028655161745451921988018943752147042304e14
// ≈ 1.26886932186e89
// minimum you can write a password using
// log(2,1.26886932186e89) ≈ 296 бит <= 37 байт
// the password will have 296 bits size
// ascii letters 126-32+1 = 95 pcs
// letter password length : log ( 95 , 1.26886932186e89 ) ≈ 45.05 letters
// <= 46 letters
//  log ( 62 , 1.26886932186e89 ) ≈ 49.71 letters <= 50 letters
//  log ( 26 , 1.26886932186e89 ) ≈ 62.97 letters <= 63 letters
//  log ( 10 , 1.26886932186e89 ) ≈ 89.1 digits <= 90 digits

# include <errno.h>
# include <string.h> // strerror
# include "struct.h"
# include "public.h"
# include "number/public.h"
# include "define.h"
# include "private.h"
# include <iso646.h> // not_eq

# ifdef SHIFR_DEBUG
void  shifr_printarr  ( shifr_strcp const  name , shifr_arrcp const p ,
  size_t const arrsize , FILE * const f ) {
  fprintf  ( f  , "%s = [ " , * name  ) ;
  uint8_t const * i = & ( ( * p ) [ 0 ] ) ;
  char const * format ;
  if ( arrsize == 0x10 )
    format = "%01hhx " ;
  else
    format = "%02hhx " ;
  do {
    fprintf ( f , format  , * i ) ;
    ++  i ;
  } while ( i not_eq  & ( ( * p ) [ arrsize ] ) ) ;
  fputs ( "]\n" , f ) ;
}
# endif

/*
Translation of the big number 'raspr.pass' to string 'password_letters'
Перевод большого числа 'raspr.pass ' в строку 'password_letters'

 0 - ''
 1 - '0' , 2 - '1'
 3 - '00' , 4 - '01' , 5 - '10' , 6 - '11'
*/

# define  shifr_password_to_string_templ_def( N ) \
void  shifr_password_to_string_templ ( N ) ( \
  shifr_number_type ( N ) const * const password0 , \
  shifr_strvp const string , shifr_strp letters , \
  uint8_t const letterscount ) { \
  char  volatile  * stringi = & ( ( * string )  [ 0 ] ) ; \
  if ( shifr_number_not_zero  ( N ) ( password0 ) ) { \
    shifr_number_priv_type ( N ) password = \
      * shifr_number_const_pub_to_priv ( N ) ( password0 ) ; \
    do { \
      /* here the previous sizes took the place of passwords */ \
      /* здесь предыдущие размеры заняли место паролей */ \
      shifr_number_dec ( N ) ( & password . pub ) ; \
      ( * stringi ) = ( * letters ) [ \
        shifr_number_div_mod ( N ) ( & password . pub , letterscount ) ] ; \
      ++  stringi ; \
    } while ( shifr_number_not_zero ( N ) ( & password . pub ) ) ; \
  } \
  ( * stringi ) = '\00' ; \
}

shifr_password_to_string_templ_def  ( v2 )
shifr_password_to_string_templ_def  ( v3 )

# include "cast.h" // int_cast_uint8

/*
'string' as string to 'password' as big number
 + create tables shifr deshi
Перевод  пароля буквами 'string' в большое число 'password'
 + создаём таблицы shifr deshi
*/
# define  shifr_string_to_password_templ_def( N ) \
void  shifr_string_to_password  ##  N ##  _templ ( \
  t_ns_shifr * const ns_shifrp , shifr_strvcp  const string , \
  shifr_number_type ( N ) * const password , shifr_strcp const letters , \
  uint8_t const letterscount  ) { \
  char  volatile  const * restrict stringi = & ( ( * string )  [ 0 ] ) ; \
  if  ( ( * stringi ) == '\00' ) { \
    shifr_number_set0 ( N ) ( password ) ; \
    goto  load  ; \
  } \
  shifr_number_priv_type ( N ) pass ; \
  shifr_number_set0 ( N ) ( & pass . pub ) ; \
  shifr_number_priv_type ( N ) mult ; \
  shifr_number_set_byte ( N ) ( & mult . pub , 1 ) ; \
  do  { \
    uint8_t i = letterscount ; \
    do { \
      -- i ; \
      if ( ( * stringi ) == ( * letters ) [ i ] ) \
        goto found ; \
    } while ( i ) ; \
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? \
      ( shifr_strcp ) & "неправильная буква в пароле" : \
      ( shifr_strcp ) & "wrong letter in password" ) ; \
    longjmp ( ns_shifrp  -> jump  , 1 ) ; \
found : ; \
    { shifr_number_priv_type ( N ) tmp = mult ; \
      shifr_number_mul_byte ( N ) ( & tmp . pub , int_cast_uint8 ( i + 1 ) ) ; \
      shifr_number_add ( N ) ( &  pass . pub , & tmp . pub ) ; \
    } \
    shifr_number_mul_byte ( N ) ( & mult . pub , letterscount ) ; \
    ++  stringi ; \
  } while ( ( * stringi ) not_eq '\00' ) ; \
  ( * shifr_number_pub_to_priv ( N ) ( password  ) ) = pass ; \
load  : \
  shifr_password_load_uni ( ns_shifrp ) ; \
}

shifr_string_to_password_templ_def  ( v2 )
shifr_string_to_password_templ_def  ( v3 )

// Отключить эхо-вывод и буферизацию ввода
// Disable echo output and input buffering
void  shifr_set_keypress  ( t_ns_shifr * const ns_shifrp ) {
  if  ( tcgetattr ( 0 , & ns_shifrp  -> stored_termios  ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      "ошибка чтения tcgetattr : %s\n" :
      "error read tcgetattr : %s\n" ) , se ) ;
    ns_shifrp  -> string_exception  = charconstp_cast_stringconstp ( se ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
  struct termios new_termios = ns_shifrp -> stored_termios  ;
  new_termios.c_lflag  and_eq int_cast_uint ( ~ ( ECHO bitor ICANON ) ) ;
  new_termios.c_cc  [ VMIN  ] = 1 ;  
  new_termios.c_cc  [ VTIME ] = 0 ; 
  if  ( tcsetattr ( 0 , TCSANOW , & new_termios ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      "ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifrp  -> string_exception  = charconstp_cast_stringconstp  ( se ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
}
 
// Восстановление дефолтного состояния
// Restoring the default state
void  shifr_reset_keypress  ( t_ns_shifr * const ns_shifrp ) {
  if  ( tcsetattr ( 0 , TCSANOW , & ns_shifrp -> stored_termios ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      "ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifrp  -> string_exception  = charconstp_cast_stringconstp ( se ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
}

uint8_t shifr_flush ( t_ns_shifr  * const ns_shifrp , shifr_arrps const output  ) {
  switch  ( ns_shifrp ->  use_version ) {
  case  2 :
    return  shifr_encrypt2_flush  ( ns_shifrp , output  ) ;
  case  3 :
    return  shifr_streambuf_writeflushzero3 ( ns_shifrp , output  ) ;
  default :
# ifdef SHIFR_DEBUG
    fprintf ( stderr , ( ns_shifrp  -> localerus ? 
      "shifr_flush : неизвестная версия %d\n" :
      "shifr_flush : unknown version %d\n" ) , ns_shifrp ->  use_version ) ;
    ns_shifrp ->  string_exception  = ( shifr_strcp ) & "shifr_flush : unknown version" ;
    longjmp ( ns_shifrp ->  jump  , 1 ) ;
# else
    return  0 ;
# endif
  }
}
  
/*
Finished buffer encryption, returns output_buffer size written
Заканчивает шифрование буфера, возвращает размер записаных данных.
*/
uint8_t shifr_encrypt2_flush  ( t_ns_shifr * const ns_shifrp , shifr_arrps const output ) {
# ifdef SHIFR_DEBUG
  if ( output . s == 0 ) {
    ns_shifrp ->  string_exception  = ( shifr_strcp ) &
      "shifr_encrypt2_flush:output . s == 0" ;
    longjmp ( ns_shifrp ->  jump  , 1 ) ;
  }
# endif // SHIFR_DEBUG
  if ( ns_shifrp  -> flagtext and ns_shifrp  -> charcount ) {
    ns_shifrp  -> charcount = 0 ;
    ( * output . p ) [ 0 ] = '\n' ;
    return  1 ;
  }
  return  0 ;
}
  
uint8_t shifr_streambuf_writeflushzero3 ( t_ns_shifr * const ns_shifrp ,
  shifr_arrps const arrpsp ) {
  uint8_t result  = 0 ;
  uint8_t * output_buffer = & ( ( * arrpsp  . p ) [ 0 ] ) ;
  if  ( ns_shifrp -> bitscount ==  0 )
    goto  lbreak ;
  ns_shifrp -> secretdata [ 0 ] = ns_shifrp -> secretdata [ ( ns_shifrp -> bitscount ==  1 ) ? 3 : 2 ] ;
  shifr_datasalt ( v3 ) ( ns_shifrp , ( shifr_arrcp ) & ns_shifrp -> secretdata ,
    & ns_shifrp -> secretdatasalt , 1 )  ;
  uint8_t secretdatasaltsize  = 1 ;  
  // после подсоления, данные переворачиваем предыдущим xor-ом
  // after settling in, we turn the data over with the previous xor
  shifr_data_xor3 ( & ns_shifrp -> old_last_data , & ns_shifrp -> old_last_salt ,
    & ns_shifrp -> secretdatasalt , secretdatasaltsize )  ;
  uint8_t encrypteddata [ 3 ] ;
  shifr_crypt_decrypt ( & ns_shifrp -> secretdatasalt , ( shifr_arrvcp )  & ns_shifrp  -> shifrv3 ,
    & encrypteddata , secretdatasaltsize ) ;
  
  size_t  writes  = 0 ;

  shifr_streambuf_write3 ( ( t_shifr_streambuf_write3 ) { . ns_shifrp = ns_shifrp ,
    . encrypteddata = ( uint8_t const ( * ) [ 3 ] ) & encrypteddata , . secretdatasaltsize = secretdatasaltsize ,
    . output_bufferp = & output_buffer , . writesp = & writes , . outputs = arrpsp . s } ) ;
  ++  result  ;

lbreak  : ;

  { shifr_t_streambuf * const me = & ns_shifrp ->  filebufto ;

    if  ( me -> bufbitsize ) {
      ( * output_buffer ) = me -> buf ;
      ++  output_buffer ;
      ++  result  ;
      me -> bufbitsize = 0 ;
    }
  } // me

  if ( ns_shifrp  -> flagtext and ( ns_shifrp ->  bytecountw  ) ) {
    ns_shifrp ->  bytecountw  = 0 ;
    ( * output_buffer ) = '\n' ;
    ++  output_buffer ;
    ++  result  ;
  }
  return  result  ;
}

// returns size loads & writes
shifr_size_io shifr_encrypt ( v2 ) ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcps const input , shifr_arrps const output  ) {
  uint8_t const * restrict  input_buffer = & ( ( * input . cp  ) [ 0 ] ) ;
  uint8_t * restrict  output_buffer = & ( ( * output  . p ) [ 0 ] ) ;
  size_t  reads = 0 ;
  size_t  writes  = 0 ;
  while ( reads < input . s and writes + 4 <= output . s ) {
    uint8_t const buf = ( * input_buffer ) ;
    ++  input_buffer  ;
    ++  reads ;
    uint8_t const secretdata  [ 4 ] = { [ 0 ]  = buf  bitand 0x3 ,
      [ 1 ] = ( buf >>  2 ) bitand 0x3 , [ 2 ] = ( buf >>  4 ) bitand 0x3 ,
      [ 3 ] = ( buf >>  6 ) bitand 0x3 } ;
    uint8_t secretdatasalt  [ 4 ] ;
    shifr_datasalt ( v2 ) ( ns_shifrp , & secretdata , & secretdatasalt , 4 )  ;
    // после подсоления, данные переворачиваем предыдущим xor-ом
    // after settling in, we turn the data over with the previous xor
    shifr_data_xor2 ( ns_shifrp , & secretdatasalt , 4 )  ;
    uint8_t encrypteddata [ 4 ] ;
    shifr_crypt_decrypt ( & secretdatasalt , ( shifr_arrvcp ) & ns_shifrp  -> shifrv2 ,
      & encrypteddata , 4 ) ;
// 2^16 ^ 1/3 = 40.32
// 2^16 % 40 = 0 .. 39
// 2^16 / 40 = 1638.4
// 1639 ^ 1/2 = 40.48
// 1639 % 40 = 0 .. 39
// 1639 / 40 = 40.97
// 2^16 = 65536
// 40 * 40 * 41 = 65600
// делаем make [0] % 40 , [1] % 40 , [2] % 41
// 'A' .. 'Z' 'a' .. 'o'
    if  ( ns_shifrp  -> flagtext  ) {
/*
 ! to get 3/4 and make 2 letters for Base64
 ! 1/4 to cache
*/
      uint16_t  buf16 = int_cast_uint16 (
        ( int_cast_uint16 ( encrypteddata [ 0 ] bitand  0xf ) ) bitor
        ( ( int_cast_uint16 ( encrypteddata [ 1 ] bitand  0xf ) ) << 4 ) bitor
        ( ( int_cast_uint16 ( encrypteddata [ 2 ] bitand  0xf ) ) << 8 ) bitor
        ( ( int_cast_uint16 ( encrypteddata [ 3 ] bitand  0xf ) ) << 12  ) ) ;
      char buf3 [ 4 ] ;
      buf3 [ 0 ] = shifr_base64_num_to_let [ buf16 % 40 ] ;
      buf16 /= 40 ;
      buf3 [ 1 ] = shifr_base64_num_to_let [ buf16 % 40 ] ;
      buf16 /= 40 ;
      buf3 [ 2 ] = shifr_base64_num_to_let [ buf16 ]  ;
      ns_shifrp  -> charcount += 3 ;
      if ( ns_shifrp  -> charcount == 60 ) {
        ns_shifrp  -> charcount = 0 ;
        buf3  [ 3 ] = '\n' ;
        memcpy  ( output_buffer , & ( buf3 [ 0 ] )  , 4 ) ;
        writes  +=  4 ;
        output_buffer +=  4 ;
      } else {
        memcpy  ( output_buffer , & ( buf3 [ 0 ] )  , 3 ) ;
        writes  +=  3 ;
        output_buffer +=  3 ;
      }
    } else {
      uint8_t const buf2 [ 2 ] = {
        [ 0 ] = int_cast_uint8  ( ( int_cast_uint16 ( encrypteddata [ 0 ] & 0xf ) )
          bitor ( (int_cast_uint16( encrypteddata [ 1 ] & 0xf ) ) << 4  ) ) ,
        [ 1 ] = int_cast_uint8  ( ( int_cast_uint16( encrypteddata [ 2 ] & 0xf ) ) bitor
          ( ( int_cast_uint16 ( encrypteddata [ 3 ] & 0xf ) ) << 4 ) ) } ;
      memcpy  ( output_buffer , & ( buf2 [ 0 ] )  , 2 ) ;
      writes  +=  2 ;
      output_buffer +=  2 ;
    }
  }
  return  ( shifr_size_io ) { .i  = reads , .o  = writes  } ;
}

// returns size loads & writes
shifr_size_io shifr_encrypt ( v3 ) ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcps const input , shifr_arrps const output  ) {
  uint8_t secretdatasaltsize  ;
  uint8_t encrypteddata [ 3 ] ;
  size_t  reads = 0 ;
  size_t  writes  = 0 ;
  uint8_t const * restrict  input_buffer = &  ( ( * input . cp  ) [ 0 ] ) ;
  uint8_t * restrict  output_buffer = & ( ( * output  . p ) [ 0 ] ) ;
  while ( reads < input . s and writes < output . s ) {
    uint8_t const buf = ( * input_buffer ) ;
    ++  input_buffer  ;
    ++  reads ;
    switch  ( ns_shifrp -> bitscount  ) {
    case  0 :
      // [ (0 1 2) (0 1 2) (0 1) ] =>
      ( ns_shifrp ->  secretdata ) [ 0 ] = buf  bitand 0x7 ;
      ( ns_shifrp ->  secretdata ) [ 1 ] = ( buf >>  3 ) bitand 0x7 ;
      ( ns_shifrp ->  secretdata ) [ 2 ] = buf >>  6 ;
      ns_shifrp ->  bitscount  = 2 ; // 0 + 8 - 6
      secretdatasaltsize  = 2 ;
      break ;
    case  1 : 
      // .. (0) ] => [ (1 2) (0 1 2) (0 1 2) ] =>
      ( ns_shifrp ->  secretdata ) [ 0 ] = int_cast_uint8 (
        ( ns_shifrp ->  secretdata ) [ 3 ] bitor ( ( buf  bitand 0x3 ) <<  1 ) ) ;
      ( ns_shifrp ->  secretdata ) [ 1 ] = ( buf >>  2 ) bitand 0x7 ;
      ( ns_shifrp ->  secretdata ) [ 2 ] = buf >>  5 ;
      ns_shifrp ->  bitscount  = 0 ;   // 1 + 8 - 9
      secretdatasaltsize  = 3 ;
      break ;
    case  2 :
      // .. (0 1) ] => [ (2) (0 1 2) (0 1 2) (0) ] =>
      ( ns_shifrp ->  secretdata ) [ 0 ] = int_cast_uint8 (
        ( ns_shifrp ->  secretdata ) [ 2 ] bitor ( ( buf  bitand 0x1 ) <<  2 ) ) ;
      ( ns_shifrp ->  secretdata ) [ 1 ] = ( buf >>  1 ) bitand 0x7 ;
      ( ns_shifrp ->  secretdata ) [ 2 ] = ( buf >>  4 ) bitand 0x7 ;
      ( ns_shifrp ->  secretdata ) [ 3 ] = buf >>  7 ;
      ns_shifrp ->  bitscount  = 1 ; // 2 + 8 - 9
      secretdatasaltsize  = 3 ;
      break ;
    default :
      fprintf ( stderr  , ( ns_shifrp -> localerus ?
        "неожиданное значение bitscount = %d\n" :
        "unexpected value bitscount = %d\n" ) , ns_shifrp -> bitscount ) ;
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? 
        ( shifr_strcp ) & "неожиданное значение bitscount" :
        ( shifr_strcp ) & "unexpected value bitscount" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; 
    } // switch  ( ns_shifrp -> bitscount  )
    shifr_datasalt ( v3 ) ( ns_shifrp , ( shifr_arrcp ) & ( ns_shifrp -> secretdata ) ,
      & ns_shifrp -> secretdatasalt , secretdatasaltsize ) ;
    // после подсоления, данные переворачиваем предыдущим ксором
    // after salting in, we turn the data over with the previous xor
    shifr_data_xor3 ( & ns_shifrp -> old_last_data , & ns_shifrp -> old_last_salt ,
      & ns_shifrp -> secretdatasalt , secretdatasaltsize ) ;
    shifr_crypt_decrypt ( & ns_shifrp -> secretdatasalt ,
      ( shifr_arrvcp  ) & ns_shifrp  -> shifrv3 , & encrypteddata , secretdatasaltsize ) ;
    shifr_streambuf_write3 ( ( t_shifr_streambuf_write3 ) { . ns_shifrp = ns_shifrp ,
      . encrypteddata = ( uint8_t const ( * ) [ 3 ] ) & encrypteddata ,
      . secretdatasaltsize = secretdatasaltsize ,
      . output_bufferp = & output_buffer , . writesp = & writes , . outputs = output . s } ) ;
  } // while
  return ( shifr_size_io ) { .i  = reads , .o  = writes  }  ;
}

// returns size loads & writes
shifr_size_io  shifr_decrypt ( v2 ) ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcps const input , shifr_arrps const output  ) {
  uint8_t const * restrict  input_buffer = &  ( ( * input . cp  ) [ 0 ] ) ;
  uint8_t * restrict  output_buffer = & ( ( * output  . p ) [ 0 ] ) ;
  size_t  reads = 0 ;
  size_t  writes  = 0 ;
  while ( reads < input . s and writes < output . s ) {
    uint8_t buf [ 2 ] ;
    if  ( ns_shifrp  -> flagtext  ) {
      // читаем три буквы ' a 1 b' -> декодируем в два байта "XY"
      // reads three letters ' a 1 b' -> decode to two bytes "XY"
      do {
        char  tmp ;
        do {
          if ( reads >= input . s or writes >= output . s )
            goto Exit ;
          tmp = uint8_cast_char ( * input_buffer ) ;
          ++  input_buffer  ;
          ++  reads ;
        } while ( ( tmp < 'a' or tmp > 'o' ) and ( tmp < 'A' or tmp > 'Z' ) ) ;
        ( ns_shifrp  -> buf2 ) [ ns_shifrp  -> buf2index ]  = tmp ;
        ++ ( ns_shifrp  -> buf2index ) ;
      } while ( ns_shifrp  -> buf2index < 3 ) ;
      // next letters begins with zero index
      // следующие буквы начинают с нулевого индекса
      ns_shifrp  -> buf2index = 0 ;
      uint16_t u16 = uint_cast_uint16 (
        ( shifr_base64_let_to_num [ ( ns_shifrp  -> buf2 ) [ 0 ] - '+' ] ) +
        40U * ( ( shifr_base64_let_to_num [ ( ns_shifrp  -> buf2 ) [ 1 ] - '+' ] ) +
        40U * ( shifr_base64_let_to_num [ ( ns_shifrp  -> buf2 ) [ 2 ] - '+' ] ) ) ) ;
      buf [ 0 ] = uint16_cast_uint8 ( u16 bitand 0xff ) ;
      buf [ 1 ] = uint16_cast_uint8 ( u16 >> 8  ) ;
    } else { // ! flagtext
      if ( reads + 1 >= input . s )
        goto Exit ;
      buf [ 0 ] = ( * input_buffer ) ;
      ++  input_buffer  ;
      ++  reads ;
      buf [ 1 ] = ( * input_buffer ) ;
      ++  input_buffer  ;
      ++  reads ;
    } // flag digit
    uint8_t secretdata  [ 4 ] = { [ 0 ] = buf [ 0 ] bitand  0xf ,
      [ 1 ] = ( buf [ 0 ] >>  4 ) bitand  0xf ,
      [ 2 ] = buf [ 1 ] bitand  0xf ,
      [ 3 ] = ( buf [ 1 ] >>  4 ) bitand  0xf  } ;
    uint8_t decrypteddata [ 4 ] ;
    shifr_decrypt_salt ( v2 ) ( & secretdata , ( shifr_arrvcp ) & ( ns_shifrp  ->
        deshiv2 ) , & decrypteddata , 4 , & ns_shifrp  -> old_last_salt ,
      & ns_shifrp  -> old_last_data ) ;
    ( * output_buffer ) = ( uint8_t ) ( ( decrypteddata [ 0 ] bitand 0x3  )
      bitor ( ( decrypteddata [ 1 ] bitand 0x3  ) << 2  )
      bitor ( ( decrypteddata [ 2 ] bitand 0x3  ) <<  4 ) bitor
      ( ( decrypteddata [ 3 ] bitand 0x3  ) << 6  ) ) ;
    ++  writes  ;
    ++  output_buffer ;
  }
Exit :
  return  ( shifr_size_io ) { .i  = reads , .o  = writes  } ;
}

shifr_size_io shifr_decrypt ( v3 ) ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcps const input , shifr_arrps const output ) {
  uint8_t const * restrict  input_buffer = &  ( ( * input . cp  ) [ 0 ] ) ;
  uint8_t * restrict  output_buffer = & ( ( * output  . p ) [ 0 ] ) ;
  size_t  reads = 0 ;
  size_t  writes  = 0 ;
  uint8_t secretdata [ 1 ] ;
  while ( ( ( reads < input . s ) or  ( ns_shifrp -> filebuffrom . bufbitsize ) ==  6 ) and
    ( writes  < output  . s ) ) {
    if ( isEOBstreambuf_read6bits ( ns_shifrp ,
      & ( secretdata [ 0 ] ) , & reads , & input_buffer , input . s ) )
      break ;
    uint8_t decrypteddata [ 1 ] ;
    shifr_decrypt_salt ( v3 ) ( & secretdata , ( shifr_arrvcp ) &
      ns_shifrp  -> deshiv3 , & decrypteddata , 1 ,
      & ns_shifrp  -> old_last_salt , & ns_shifrp  -> old_last_data ) ;
    shifr_streambuf_write3bits ( ns_shifrp , decrypteddata [ 0 ] , &
      output_buffer , & writes ) ;
  } // while
  return  ( shifr_size_io ) { . i  = reads , .  o  = writes  } ;
}

# define  shifr_generate_dices_def( ver , rasprname ) \
void  shifr_generate_dices ( ver ) ( t_ns_shifr * const ns_shifrp ) {  \
  uint8_t volatile  * j = & ( ns_shifrp -> rasprname . dice [ 0 ] ) ;  \
  uint8_t i  = shifr_deshi_size ( ver ) - 1 ;  \
  struct  s_shifr_fr_to volatile  ft = {  \
    . sh = ns_shifrp ,  \
    . fr = 0 ,  \
  } ; \
  do {  \
    ft  . to  = i ; \
    shifr_uirandfrto  ( & ft )  ; \
    ( * j ) = uint_cast_uint8 ( ft . res ) ; \
    --  i ; \
    ++  j ; \
  } while ( i >= 1 ) ;  \
  ft  . sh  = 0 ; \
  ft  . to  = 0 ; \
  ft  . res = 0 ; \
}

// ! to remove , make random 0..16!-1
// generate array raspr2.dice
// inits array [ 0..15 , 0..14 , ... , 0..2 , 0..1 ]
shifr_generate_dices_def  ( v2 , raspr2 )

// ! to remove , make random 0..64!-1
// generate array raspr3.dice
// inits array [ 0..63 , 0..62 , ... , 0..2 , 0..1 ]
shifr_generate_dices_def  ( v3 , raspr3 )

# define  shifr_dices_to_number_def( ver , rasprname ) \
void  shifr_dices_to_number ( ver ) ( t_ns_shifr * const ns_shifrp ) { \
  shifr_number_set0 ( ver ) ( & ns_shifrp -> rasprname . pass . pub ) ; \
  shifr_number_priv_type ( ver ) mu  ; \
  shifr_number_set_byte ( ver ) ( & mu . pub , 1 ) ; \
  uint8_t in = 0 ; \
  do { \
    { shifr_number_priv_type ( ver ) mux = mu ; \
      /* re += dice [ in ] * mu ; */ \
      shifr_number_mul_byte ( ver ) ( & mux . pub , \
        ns_shifrp -> rasprname . dice [ in ] ) ; \
      shifr_number_add  ( ver ) ( & ns_shifrp -> rasprname . pass . pub , \
        & mux . pub ) ; \
    } \
    /* $mu *=  16|64 - $in ; */ \
    shifr_number_mul_byte ( ver ) ( & mu . pub , \
      int_cast_uint8 ( shifr_deshi_size ( ver ) - in ) ) ; \
    ++  in ; \
  } while ( in < shifr_deshi_size ( ver ) - 1 ) ; \
  shifr_password_from_dice_uni  ( ns_shifrp ) ; \
}

// convert raspr2.dice as array to big number raspr2.pass
//  + create tables shifr deshi
// [ 0..15 , 0..14 , 0..13 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ]
// = x + y * 16 + z * 16 * 15 + ... + u * 16! / 2 / 3 + v * 16! / 2 =
// 0 .. 16!-1
shifr_dices_to_number_def ( v2 , raspr2 )

// convert raspr3.dice as array to big number raspr3.pass
//  + create tables shifr deshi
// [ 0..63 , 0..62 , 0..61 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ]
// = x + y * 64 + z * 64 * 63 + ... + u * 64! / 2 / 3 + v * 64! / 2 = 
// 0 .. 64!-1
shifr_dices_to_number_def ( v3 , raspr3 )

# define  shifr_password_set_by_string_templ( ver , password_letters_name ) \
  strncpy ( charvolatilep_cast_charp ( & \
    ns_shifrp  -> password_letters_name [ 0 ] ) , pswstr , \
    shifr_password_letters_size ( ver ) ) ; \
  if ( ns_shifrp  -> password_letters_name [ shifr_password_letters_size ( ver ) - 1 ] \
    != '\00' ) { \
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? \
      ( shifr_strcp ) & \
      "shifr_password_set_by_string ( " # ver " ) : пароль очень длинный" : \
      ( shifr_strcp ) & \
      "shifr_password_set_by_string ( " # ver " ) : the password is very long" ) ; \
    longjmp ( ns_shifrp  -> jump  , 1 ) ; \
  } \
  break ;

void  shifr_password_set_by_string ( t_ns_shifr * const ns_shifrp ,
  char const * const pswstr ) {
  switch ( ns_shifrp -> use_version ) {
  case  2 :
    shifr_password_set_by_string_templ  ( v2 , password_letters2 )
  case  3 :
    shifr_password_set_by_string_templ  ( v3 , password_letters3 )
  default :
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & "shifr_password_set_by_string : неизвестная версия" :
      ( shifr_strcp ) & "shifr_password_set_by_string : unknown version" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
  shifr_string_to_password  ( ns_shifrp ) ;
}

# define  shifr_string_to_password_case( ver , shifr_letters_count_name , password_letters_name , raspr_name , letters_name ) \
  case  shifr_letters_count_name : \
    shifr_string_to_password_templ  ( ver ) ( ns_shifrp , \
      ( shifr_strvcp  ) & ns_shifrp  -> password_letters_name , \
      & ns_shifrp -> raspr_name  . pass . pub , \
      ( shifr_strcp ) & ns_shifrp -> letters_name ,  shifr_letters_count_name ) ; \
    break ;

/*
transfer 'password_letters' as string to 'raspr.pass' as big number
 + create tables shifr deshi
Перевод  пароля буквами 'password_letters' в большое число 'raspr.pass'
 + создаём таблицы shifr deshi
*/
void  shifr_string_to_password ( t_ns_shifr * const ns_shifrp ) {
  switch ( ns_shifrp -> use_version ) {
  case 2 :
    switch  ( ns_shifrp -> password_alphabet  ) {
    shifr_string_to_password_case ( v2 , shifr_letters_count , password_letters2 , raspr2 , letters )
    shifr_string_to_password_case ( v2 , shifr_letters_count62 , password_letters2 , raspr2 , letters62 )
    shifr_string_to_password_case ( v2 , shifr_letters_count52 , password_letters2 , raspr2 , letters52 )
    shifr_string_to_password_case ( v2 , shifr_letters_count_Digit , password_letters2 , raspr2 , letters_Digit )
    shifr_string_to_password_case ( v2 , shifr_letters_count4 , password_letters2 , raspr2 , letters4 )
    default :
      goto  Exc ;
    }
    break ;
  case 3 :
    switch  ( ns_shifrp -> password_alphabet  ) {
    shifr_string_to_password_case ( v3 , shifr_letters_count , password_letters3 , raspr3 , letters )
    shifr_string_to_password_case ( v3 , shifr_letters_count62 , password_letters3 , raspr3 , letters62 )
    shifr_string_to_password_case ( v3 , shifr_letters_count52 , password_letters3 , raspr3 , letters52 )
    shifr_string_to_password_case ( v3 , shifr_letters_count_Digit , password_letters3 , raspr3 , letters_Digit )
    shifr_string_to_password_case ( v3 , shifr_letters_count4 , password_letters3 , raspr3 , letters4 )
    default :
Exc :
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) & "string_to_password : версия алфавита не известна" :
        ( shifr_strcp ) & "string_to_password : alphabet version is not known" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ;
    }
    break ;
  default :
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      "string_to_password : версия %d не поддерживается\n" :
      "string_to_password : version %d is not supported\n" ) ,
      ns_shifrp -> use_version )  ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & "string_to_password : версия не поддерживается" :
      ( shifr_strcp ) & "string_to_password : version is not supported" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
}

/*
 Translation of big number 'raspr.pass' 
to the encryption table 'shifr', decryption 'deshi'
 Перевод большого числа 'raspr.pass' в таблицы шифрования 'shifr' ,
дешифровки 'deshi'
*/
void  shifr_password_load_uni ( t_ns_shifr * const ns_shifrp ) {
  switch ( ns_shifrp -> use_version ) {
  case 2 :
    shifr_password_load ( v2  ) ( & ns_shifrp -> raspr2  . pass . pub ,
      & ns_shifrp  -> shifrv2 , & ns_shifrp  -> deshiv2 ) ;
    break ;
  case 3 :
    shifr_password_load ( v3  ) ( & ns_shifrp -> raspr3  . pass . pub ,
      & ns_shifrp  -> shifrv3 , & ns_shifrp  -> deshiv3 ) ;
    break ;
  default :
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      "password_load:версия %d не поддерживается\n" :
      "password_load:version %d is not supported" ) ,
      ns_shifrp -> use_version )  ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & "password_load:версия не поддерживается" :
      ( shifr_strcp ) & "password_load:version is not supported" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
}

/*
 Translation of big number 'raspr.pass' 
to the encryption table 'shifr', decryption 'deshi'
 Перевод большого числа 'raspr.pass' в таблицы шифрования 'shifr' ,
дешифровки 'deshi'
*/
void  shifr_password_from_dice_uni ( t_ns_shifr * const ns_shifrp ) {
  switch ( ns_shifrp -> use_version ) {
  case 2 :
    shifr_password_from_dice ( v2 ) ( ns_shifrp  -> raspr2 . dice ,
      & ns_shifrp  -> shifrv2 , & ns_shifrp  -> deshiv2 ) ;
    break ;
  case 3 :
    shifr_password_from_dice ( v3 ) ( ns_shifrp  -> raspr3 . dice , 
      & ns_shifrp  -> shifrv3 , & ns_shifrp  -> deshiv3 ) ;
    break ;
  default :
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      "password_from_dice:версия %d не поддерживается\n" :
      "password_from_dice:version %d is not supported" ) ,
      ns_shifrp -> use_version )  ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & "password_from_dice:версия не поддерживается" :
      ( shifr_strcp ) & "password_from_dice:version is not supported" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
}
    
/*
Translation of the big number 'raspr.pass' to string 'password_letters'
Перевод большого числа 'raspr.pass ' в строку 'password_letters'

 0 - ''
 1 - '0' , 2 - '1'
 3 - '00' , 4 - '01' , 5 - '10' , 6 - '11'
*/
void  shifr_password_to_string  ( t_ns_shifr * const ns_shifrp ) {
  switch  ( ns_shifrp -> use_version ) {
  case  2 :
    switch  ( ns_shifrp -> password_alphabet  ) {
    case  shifr_letters_count :
      shifr_password_to_string_templ  ( v2 ) (
        & ns_shifrp -> raspr2  . pass . pub ,
        & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters ,
        shifr_letters_count ) ;
      break ;
    case  shifr_letters_count62  :
      shifr_password_to_string_templ  ( v2 ) (
        & ns_shifrp -> raspr2  . pass . pub ,
        & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters62 ,
        shifr_letters_count62 ) ;
      break ;
    case  shifr_letters_count52  :
      shifr_password_to_string_templ  ( v2 ) (
        & ns_shifrp -> raspr2  . pass . pub ,
        & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters52 ,
        shifr_letters_count52 ) ;
      break ;
    case  shifr_letters_count_Digit  :
      shifr_password_to_string_templ  ( v2 ) (
        & ns_shifrp -> raspr2  . pass . pub ,
        & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters_Digit ,
        shifr_letters_count_Digit ) ;
      break ;
    case  shifr_letters_count4  :
      shifr_password_to_string_templ  ( v2 ) (
        & ns_shifrp -> raspr2  . pass . pub ,
        & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters4 ,
        shifr_letters_count4 ) ;
      break ;
    default :
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) & "password_to_string:версия алфавита не известна" :
        ( shifr_strcp ) & 
        "password_to_string:alphabet version is not known" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ;
    }
    break ;
  case 3 :
    switch  ( ns_shifrp -> password_alphabet  ) {
    case  shifr_letters_count :
      shifr_password_to_string_templ  ( v3 ) (
        & ns_shifrp -> raspr3  . pass . pub ,
        & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters ,
        shifr_letters_count ) ;
      break ;
    case  shifr_letters_count62  :
      shifr_password_to_string_templ  ( v3 ) (
        & ns_shifrp -> raspr3  . pass . pub ,
        & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters62 ,
        shifr_letters_count62 ) ;
      break ;
    case  shifr_letters_count52  :
      shifr_password_to_string_templ  ( v3 ) (
        & ns_shifrp -> raspr3  . pass . pub ,
        & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters52 ,
        shifr_letters_count52 ) ;
      break ;
    case  shifr_letters_count_Digit  :
      shifr_password_to_string_templ  ( v3 ) (
        & ns_shifrp -> raspr3  . pass . pub ,
        & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters_Digit ,
        shifr_letters_count_Digit ) ;
      break ;
    case  shifr_letters_count4  :
      shifr_password_to_string_templ  ( v3 ) (
        & ns_shifrp -> raspr3  . pass . pub ,
        & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters4 ,
        shifr_letters_count4 ) ;
      break ;
    default :
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) & "password_to_string:версия алфавита не известна" :
        ( shifr_strcp ) & 
        "password_to_string:alphabet version is not known" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ;
    }
    break ;
  default :
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      "password_to_string:версия %d не поддерживается\n" :
      "password_to_string:version %d is not supported" ) ,
      ns_shifrp -> use_version )  ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & "password_to_string:версия не поддерживается" :
      ( shifr_strcp ) & "password_to_string:version is not supported" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
}
  
void  volatile  * shifr_memsetv ( void  volatile  * const str ,
  uint8_t const ch  , size_t  n ) {
  uint8_t volatile  * p = str ;
  while ( n ) {
    * p = ch  ;
    --  n ;
    ++  p ;
  }
  return  str ;
}

void  shifr_destr ( t_ns_shifr * const ns_shifrp ) {
  shifr_memsetv ( ns_shifrp ->  password_letters2 , shifr_memsetv_default_byte ,
    sizeof  ( ns_shifrp ->  password_letters2 ) ) ;
  shifr_memsetv ( ns_shifrp ->  password_letters3 , shifr_memsetv_default_byte ,
    sizeof  ( ns_shifrp ->  password_letters3 ) ) ;
  shifr_memsetv ( ns_shifrp ->  shifrv2 , shifr_memsetv_default_byte ,
    sizeof  ( ns_shifrp ->  shifrv2 ) ) ;
  shifr_memsetv ( ns_shifrp ->  shifrv3 , shifr_memsetv_default_byte ,
    sizeof  ( ns_shifrp ->  shifrv3 ) ) ;
  shifr_memsetv ( ns_shifrp ->  deshiv2 , shifr_memsetv_default_byte ,
    sizeof  ( ns_shifrp ->  deshiv2 ) ) ;
  shifr_memsetv ( ns_shifrp ->  deshiv3 , shifr_memsetv_default_byte ,
    sizeof  ( ns_shifrp ->  deshiv3 ) ) ;
}

void  shifr_salt_init ( t_ns_shifr  * const ns_shifrp ) {
  ns_shifrp ->  old_last_data = 0 ;
  ns_shifrp ->  old_last_salt = 0 ;
  ns_shifrp ->  filebuffrom . buf = 0 ;
  ns_shifrp ->  filebuffrom . bufbitsize  = 0 ;
  ns_shifrp ->  filebufto . buf = 0 ;
  ns_shifrp ->  filebufto . bufbitsize  = 0 ;
  ns_shifrp ->  bytecountw  = 0 ;
  ns_shifrp ->  buf2index = 0 ;
  ns_shifrp ->  bitscount = 0 ;
  ns_shifrp ->  charcount = 0 ;
  for ( int i = 0 ; i < 3 ; ++  i )
    ns_shifrp ->  secretdatasalt  [ i ] = 0 ;
  for ( int i = 0 ; i < 4 ; ++  i )
    ns_shifrp ->  secretdata  [ i ] = 0 ;
  for ( int i = 0 ; i < 3 ; ++  i )
    ns_shifrp ->  buf2  [ i ] = 0 ;
}

# define  shifr_password_from_dice_def(  N , SDS ) \
void  shifr_password_from_dice  ( N ) ( uint8_t volatile  const * const dice  , \
  shifr_arrvp const shifrp , shifr_arrvp  const deship ) { \
  shifr_initarr ( shifrp  , 0xff  , SDS ) ; \
  shifr_initarr ( deship  , 0xff  , SDS ) ; \
  uint8_t volatile  arrind  [ SDS ] ; \
  { uint8_t volatile  * arrj  = & ( arrind  [ SDS  ] ) ; \
    uint8_t j = SDS  ; \
    do  { \
      --  arrj  ; \
      --  j ; \
      ( * arrj )  = j ; \
    } while ( arrj  not_eq & ( arrind  [ 0 ] ) ) ; \
  } \
  uint8_t inde  = 0 ; \
  do { \
    { uint8_t const cindex  = \
        ( inde == SDS - 1 ? \
          0 : \
          dice  [ inde  ] ) ; \
      uint8_t volatile  * const arrind_cindexp = & ( arrind [ cindex ] ) ; \
      ( * shifrp ) [ inde ] = ( * arrind_cindexp ) ;  \
      ( * deship ) [ * arrind_cindexp ] = inde ;  \
      memmove ( uint8volatilep_cast_unt8p ( arrind_cindexp ) ,  \
        uint8volatilep_cast_unt8p ( arrind_cindexp ) + 1 , \
        int_cast_size ( SDS  - inde  - cindex - 1 ) ) ; \
    } \
    ++ inde  ; \
  } while ( inde < SDS ) ; \
  shifr_memsetv ( arrind  , shifr_memsetv_default_byte , sizeof  ( arrind  ) ) ; \
}

shifr_password_from_dice_def (  v2 , shifr_deshi_size ( v2 ) )
shifr_password_from_dice_def (  v3 , shifr_deshi_size ( v3 ) )

# define  shifr_password_load_def(  N , SDS ) \
void  shifr_password_load ( N ) ( shifr_number_type ( N ) const * const password0 , \
  shifr_arrvp const shifrp , shifr_arrvp  const deship ) { \
  shifr_initarr ( shifrp  , 0xff  , SDS ) ; \
  shifr_initarr ( deship  , 0xff  , SDS ) ; \
  uint8_t volatile  arrind  [ SDS ] ; \
  { uint8_t volatile  * arrj  = & ( arrind  [ SDS  ] ) ; \
    uint8_t j = SDS  ;  \
    do  { \
      --  arrj  ; \
      --  j ; \
      ( * arrj )  = j ; \
    } while ( arrj  not_eq & ( arrind  [ 0 ] ) ) ; \
  } \
  uint8_t inde  = 0 ; \
  shifr_number_priv_type ( N ) password = \
    * shifr_number_const_pub_to_priv ( N ) ( password0 ) ; \
  do { \
    { uint8_t const cindex = shifr_number_div_mod ( N ) ( & password . pub ,  \
        int_cast_uint8 ( SDS - inde  ) ) ; \
      uint8_t volatile  * const arrind_cindexp = & ( arrind [ cindex ] ) ; \
      ( * shifrp ) [ inde ] = ( * arrind_cindexp ) ;  \
      ( * deship ) [ * arrind_cindexp ] = inde ;  \
      memmove ( uint8volatilep_cast_unt8p ( arrind_cindexp ) , \
        uint8volatilep_cast_unt8p ( arrind_cindexp ) + 1 , \
        int_cast_size ( SDS  - inde  - cindex - 1 ) ) ; \
    } \
    ++ inde  ; \
  } while ( inde < SDS ) ; \
  shifr_memsetv ( arrind  , shifr_memsetv_default_byte , sizeof  ( arrind  ) ) ; \
}

shifr_password_load_def (  v2 , shifr_deshi_size ( v2 ) )
shifr_password_load_def (  v3 , shifr_deshi_size ( v3 ) )

# ifdef SHIFR_DEBUG
# define  shifr_decode_file_debug \
  if ( sizeio . i < readcount ) { \
    fprintf ( stderr  , "sizeio . i = %zu , readcount = %zu\n"  , sizeio . i , readcount ) ;  \
    main_shifrp -> string_exception  = ( shifr_strcp ) & "sizeio . i < readcount" ; \
    longjmp ( main_shifrp -> jump  , 1 ) ;  \
  }
# else
# define  shifr_decode_file_debug
# endif

# define  shifr_decode_file_templ(  V ) \
void  shifr_decode_file ( V ) ( t_ns_shifr  * const main_shifrp , \
  uint8_t ( * const inputbufferp  ) [ ] , size_t  const inputbuffersize , \
  uint8_t ( * const outputbufferp ) [ ] , size_t  const outputbuffersize  ) { \
  size_t  writecount  ; \
  shifr_size_io sizeio  ; \
  do  { \
    size_t const  readcount = fread ( & ( ( * inputbufferp  ) [ 0 ] ) , 1 , \
      inputbuffersize , main_shifrp -> filebuffrom . file ) ; \
    if ( readcount  ) { \
      sizeio  = shifr_decrypt ( V ) ( main_shifrp , \
        ( shifr_arrcps ) { .cp = ( shifr_arrcp ) inputbufferp , .s = readcount } , \
        ( shifr_arrps ) { .p = outputbufferp , .s = outputbuffersize } ) ;  \
      shifr_decode_file_debug \
      writecount = fwrite ( & ( ( * outputbufferp ) [ 0 ] ) , sizeio . o , 1 ,  \
        main_shifrp -> filebufto . file ) ; \
      if ( writecount == 0 ) {  \
        main_shifrp -> string_exception  = ( main_shifrp -> localerus ? \
          ( shifr_strcp ) & "ошибка записи в файл" :  \
          ( shifr_strcp ) & "error writing to file" ) ; \
        longjmp ( main_shifrp -> jump  , 1 ) ;  \
      } \
      if ( feof ( main_shifrp -> filebuffrom . file ) ) \
        break ; \
    } else { /* if readcount */ \
      if ( ferror ( main_shifrp -> filebuffrom . file ) ) { \
        main_shifrp -> string_exception  = ( main_shifrp -> localerus ? \
          ( shifr_strcp ) & "ошибка чтения файла" : \
          ( shifr_strcp ) & "error reading the file" ) ;  \
        longjmp ( main_shifrp -> jump  , 1 ) ;  \
      } \
      break ; \
    } \
  } while ( true  ) ; \
}

shifr_decode_file_templ ( v2  )
shifr_decode_file_templ ( v3  )

# ifdef SHIFR_DEBUG
# define  shifr_encode_file_debug \
  if ( sizeio . i < readcount ) { \
    fprintf ( stderr  , "sizeio . i = %zu , readcount = %zu\n"  ,  sizeio . i , readcount ) ; \
    main_shifrp -> string_exception  = ( shifr_strcp ) & "sizeio . i < readcount" ; \
    longjmp ( main_shifrp -> jump  , 1 ) ;  \
  } \
  if ( sizeio . o > outputbuffersize ) {  \
    fprintf ( stderr  , "sizeio . o = %zu , outputbuffersize = %zu\n" , sizeio . o , outputbuffersize ) ; \
    main_shifrp -> string_exception  = ( shifr_strcp ) & "sizeio . o > outputbuffersize" ;  \
    longjmp ( main_shifrp -> jump  , 1 ) ;  \
  }
# else
# define  shifr_encode_file_debug
# endif

# define  shifr_encode_file_templ(  V ) \
void  shifr_encode_file ( V ) ( t_ns_shifr  * const main_shifrp , \
  uint8_t ( * const inputbufferp  ) [ ] , size_t  const inputbuffersize , \
  uint8_t ( * const outputbufferp ) [ ] , size_t  const outputbuffersize  ) { \
  size_t  writecount  ; \
  shifr_size_io sizeio  ; \
  do  { \
    size_t const  readcount = fread ( & ( ( * inputbufferp  ) [ 0 ] ) , \
      1 , inputbuffersize , main_shifrp -> filebuffrom . file ) ; \
    if ( readcount  ) { \
      sizeio  = shifr_encrypt ( V ) ( main_shifrp , \
        ( shifr_arrcps ) { .cp = ( shifr_arrcp ) inputbufferp , .s = readcount } ,  \
        ( shifr_arrps ) { .p = outputbufferp , .s = outputbuffersize } ) ;  \
      shifr_encode_file_debug \
      writecount = fwrite ( & ( ( * outputbufferp ) [ 0 ] ) , sizeio . o ,  \
        1 , main_shifrp -> filebufto . file ) ; \
      if ( writecount == 0 )  \
        goto Exc ;  \
      if ( feof ( main_shifrp -> filebuffrom . file ) ) \
        break ; \
    } else {  \
      if ( ferror ( main_shifrp -> filebuffrom . file ) ) { \
        main_shifrp -> string_exception  = ( main_shifrp -> localerus ? \
          ( shifr_strcp ) & "ошибка чтения файла" : \
          ( shifr_strcp ) & "error reading the file" ) ;  \
        longjmp ( main_shifrp -> jump  , 1 ) ;  \
      } \
      break ; \
    } \
  } while ( true ) ;  \
  { uint8_t const bytes = shifr_flush ( main_shifrp , \
      ( shifr_arrps ) { .p = outputbufferp , .s = outputbuffersize } ) ;  \
    if ( bytes ) {  \
      writecount = fwrite ( & ( ( * outputbufferp ) [ 0 ] ) , bytes , 1 , \
        main_shifrp -> filebufto . file ) ; \
      if ( writecount == 0 ) {  \
Exc : \
        main_shifrp -> string_exception  = ( main_shifrp -> localerus ? \
          ( shifr_strcp ) & "ошибка записи в файл" :  \
          ( shifr_strcp ) & "error writing to file" ) ; \
          longjmp ( main_shifrp -> jump  , 1 ) ;  \
      } \
    } \
  } \
}

shifr_encode_file_templ ( v2  )
shifr_encode_file_templ ( v3  )

void  shifr_test_password ( t_ns_shifr  * const main_shifrp , size_t  const nr  ) {
  char  volatile  * const psw_uni =
    ( ( main_shifrp -> use_version == 2 ) ?
        main_shifrp -> password_letters2 :
        main_shifrp -> password_letters3 ) ;
  psw_uni [ nr ] = '\00' ;

  switch  ( main_shifrp -> password_alphabet  ) {
  case  shifr_letters_count :
    { size_t i  = 0 ;
      for ( ; i < nr  ; ++  i ) {
        if ( psw_uni [ i ] < ' ' or psw_uni  [ i ] > '~' ) {
          psw_uni [ i ] = '\00' ;
          break ;
        }
      }
    }
    break ;
  case  shifr_letters_count62  :
    { size_t i  = 0 ;
      char  volatile  psw_unii  ;
      for ( ; i < nr  ; ++  i ) {
        psw_unii  = psw_uni [ i ] ;
        if ( ( psw_unii < '0' or  psw_unii > '9' ) and
          ( psw_unii < 'a' or psw_unii > 'z' ) and
          ( psw_unii < 'A' or psw_unii > 'Z' ) ) {
          psw_uni [ i ] = '\00' ;
          break ;
        }
      }
      psw_unii  = shifr_memsetv_default_byte ;
    }
    break ;
  case  shifr_letters_count52  :
    { size_t i  = 0 ;
      char  volatile  psw_unii  ;
      for ( ; i < nr  ; ++  i ) {
        psw_unii  = psw_uni [ i ] ;
        if ( ( psw_unii < 'a' or psw_unii > 'z' ) and
          ( psw_unii < 'A' or psw_unii > 'Z' ) ) {
          psw_uni [ i ] = '\00' ;
          break ;
        }
      }
      psw_unii  = shifr_memsetv_default_byte ;
    }
    break ;
  case  shifr_letters_count_Digit  :
    { size_t i  = 0 ;
      for ( ; i < nr  ; ++  i ) {
        if (  psw_uni [ i ] < '0' or  psw_uni  [ i ] > '9' ) {
          psw_uni [ i ] = '\00' ;
          break ;
        }
      }
    }
    break ;
  case  shifr_letters_count4  :
    { size_t i  = 0 ;
      for ( ; i < nr  ; ++  i ) {
        if (  psw_uni [ i ] < 'a' or  psw_uni  [ i ] > 'z' ) {
          psw_uni [ i ] = '\00' ;
          break ;
        }
      }
    }
    break ;
  default :
    main_shifrp -> string_exception  = ( main_shifrp -> localerus ?
      ( shifr_strcp ) & "неизвестный алфавит пароля" :
      ( shifr_strcp ) & "unknown password alphabet" ) ;
    longjmp ( main_shifrp -> jump  , 1 ) ;
  }
}

// generate big number as password, convert to string and puts
// in debug mode creates tables shifr deshi many times
void  shifr_main_genpsw ( t_ns_shifr  * const main_shifrp ) {
  shifr_generate_password ( main_shifrp ) ;
  bool  const localerus = main_shifrp -> localerus  ;
# ifdef SHIFR_DEBUG
  switch ( main_shifrp -> use_version ) {
  case  2 :
    fputs ( ( localerus ?
      "внутренний пароль = " :
      "internal password = " ) , stderr ) ;
    shifr_number_princ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub , stderr  ) ;
    fputs ( "\n" , stderr ) ;
    break ;
  case  3 :
    fputs ( ( localerus ?
      "внутренний пароль = " :
      "internal password = " ) , stderr ) ;
    shifr_number_princ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub , stderr  ) ;
    fputs ( "\n" , stderr ) ;
    break ;
  default :
    fprintf ( stderr , ( localerus ?
      "flaggenpasswd : неопознанная версия : \'%d\'\n" :
      "flaggenpasswd : unrecognized version : \'%d\'\n" ) ,
      main_shifrp -> use_version ) ;
    main_shifrp -> string_exception  = ( localerus ?
      ( shifr_strcp ) & "flaggenpasswd : неопознанная версия" :
      ( shifr_strcp ) & "flaggenpasswd : unrecognized version" ) ;
    longjmp ( main_shifrp -> jump  , 1 ) ;
  }
  char  volatile  password_letters2_62  [ shifr_password_letters_size ( v2 ) ] ;
  char  volatile  password_letters3_62  [ shifr_password_letters_size ( v3 ) ] ;
  char  volatile  password_letters2_52  [ shifr_password_letters_size ( v2 ) ] ;
  char  volatile  password_letters3_52  [ shifr_password_letters_size ( v3 ) ] ;
  char  volatile  password_letters2_10  [ shifr_password_letters_size ( v2 ) ] ;
  char  volatile  password_letters3_10  [ shifr_password_letters_size ( v3 ) ] ;
  char  volatile  password_letters2_26  [ shifr_password_letters_size ( v2 ) ] ;
  char  volatile  password_letters3_26  [ shifr_password_letters_size ( v3 ) ] ;
  switch  ( main_shifrp -> use_version ) {
  case  2 :
    shifr_password_to_string_templ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub ,
      & main_shifrp -> password_letters2 , & main_shifrp -> letters ,
      shifr_letters_count ) ;
    shifr_password_to_string_templ  ( v2 ) (
      & main_shifrp -> raspr2  . pass . pub ,
      & password_letters2_62  , & main_shifrp -> letters62 , shifr_letters_count62 ) ;
    shifr_password_to_string_templ  ( v2 ) (
      & main_shifrp -> raspr2  . pass . pub ,
      & password_letters2_52  , & main_shifrp -> letters52 , shifr_letters_count52 ) ;
    shifr_password_to_string_templ  ( v2 ) (
      & main_shifrp -> raspr2  . pass . pub ,
      & password_letters2_10 , & main_shifrp -> letters_Digit , shifr_letters_count_Digit ) ;
    shifr_password_to_string_templ  ( v2 ) (
      & main_shifrp -> raspr2  . pass . pub ,
      & password_letters2_26  , & main_shifrp -> letters4 , shifr_letters_count4 ) ;
    break ;
  case  3 :
    shifr_password_to_string_templ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub ,
      & main_shifrp -> password_letters3 , & main_shifrp -> letters ,
      shifr_letters_count ) ;
    shifr_password_to_string_templ  ( v3 ) (
      & main_shifrp -> raspr3  . pass . pub ,
      & password_letters3_62  , & main_shifrp -> letters62 , shifr_letters_count62 ) ;
    shifr_password_to_string_templ  ( v3 ) (
      & main_shifrp -> raspr3  . pass . pub ,
      & password_letters3_52  , & main_shifrp -> letters52 , shifr_letters_count52 ) ;
    shifr_password_to_string_templ  ( v3 ) (
      & main_shifrp -> raspr3  . pass . pub ,
      & password_letters3_10  , & main_shifrp -> letters_Digit , shifr_letters_count_Digit ) ;
    shifr_password_to_string_templ  ( v3 ) (
      & main_shifrp -> raspr3  . pass . pub ,
      & password_letters3_26  , & main_shifrp -> letters4 , shifr_letters_count4 ) ;
    break ;
  default :
    fprintf ( stderr , ( localerus ?
      "показать пароль : неопознанная версия : \'%d\'\n" :
      "show password : unrecognized version : \'%d\'\n" ) ,
      main_shifrp -> use_version ) ;
    main_shifrp -> string_exception  = ( localerus ?
      ( shifr_strcp ) & "показать пароль : неопознанная версия" :
      ( shifr_strcp ) & "show password : unrecognized version" ) ;
    longjmp ( main_shifrp -> jump  , 1 ) ;
  }
  fprintf  ( stderr , ( localerus ?
    "--a95\tбуквами, знаками между кавычек = \'%s\'\n" :
    "--a95\tby letters, signs between quotes = \'%s\'\n"  ) ,
    & ( ( ( main_shifrp -> use_version == 3 ) ?
      main_shifrp -> password_letters3 :
      main_shifrp -> password_letters2 ) [ 0 ] ) ) ;
  fprintf  ( stderr , ( localerus ?
    "--a62\tбуквами, цифрами между кавычек = \'%s\'\n" :
    "--a62\tby letters, digits between quotes = \'%s\'\n"  ) ,
    & ( ( ( main_shifrp -> use_version == 3 ) ? password_letters3_62  :
      password_letters2_62  ) [ 0 ] ) ) ;
  fprintf  ( stderr , ( localerus ?
    "--a52\tбольшими и маленькими буквами между кавычек = \'%s\' (по-умолчанию)\n" :
    "--a52\tlarge and small letters between quotation marks = \'%s\' (by default)\n"  ) ,
    & ( ( ( main_shifrp -> use_version == 3 ) ? password_letters3_52  :
      password_letters2_52  ) [ 0 ] ) ) ;
  fprintf  ( stderr , ( localerus ?
    "--a26\tмаленькими буквами между кавычек = \'%s\'\n" :
    "--a26\tby small letters between quotes = \'%s\'\n"  ) ,
    & ( ( ( main_shifrp -> use_version == 3 ) ? password_letters3_26 :
      password_letters2_26  ) [ 0 ] ) ) ;
  fprintf  ( stderr , ( localerus ?
    "--a10 --adig\tцифрами между кавычек = \'%s\'\n" :
    "--a10 --adig\tby digits between quotes = \'%s\'\n"  ) ,
    & ( ( ( main_shifrp -> use_version == 3 ) ? password_letters3_10 :
      password_letters2_10 )  [ 0 ] ) ) ;
  switch  ( main_shifrp -> use_version ) {
  case  2 :
    { shifr_number_priv_type ( v2 ) password2 ;

      shifr_string_to_password_templ  ( v2 ) ( main_shifrp ,
        ( shifr_strvcp  ) & main_shifrp -> password_letters2 ,
        & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters , shifr_letters_count ) ;
      fputs ( ( localerus ?
        "из строки95 во внутренний пароль = " :
        "from string95 to internal password = " ) , stderr ) ;
      shifr_number_princ  ( v2 ) ( & password2 . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;

      shifr_string_to_password_templ  ( v2 ) ( main_shifrp ,
        ( shifr_strvcp  ) & password_letters2_62  ,
        & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters62 , shifr_letters_count62 ) ;
      fputs ( ( localerus ?
        "из строки62 во внутренний пароль = " :
        "from string62 to internal password = " ) , stderr ) ;
      shifr_number_princ  ( v2 ) ( & password2 . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;

      shifr_string_to_password_templ  ( v2 ) ( main_shifrp ,
        ( shifr_strvcp  ) & password_letters2_52  ,
        & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters52 , shifr_letters_count52 ) ;
      fputs ( ( localerus ?
        "из строки52 во внутренний пароль = " :
        "from string52 to internal password = " ) , stderr ) ;
      shifr_number_princ  ( v2 ) ( & password2 . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;

      shifr_string_to_password_templ  ( v2 ) ( main_shifrp ,
        ( shifr_strvcp  ) & password_letters2_26  ,
        & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters4 , shifr_letters_count4 ) ;
      fputs ( ( localerus ?
        "из строки26 во внутренний пароль = " :
        "from string26 to internal password = " ) , stderr ) ;
      shifr_number_princ  ( v2 ) ( & password2 . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;

      shifr_string_to_password_templ  ( v2 ) ( main_shifrp ,
        ( shifr_strvcp  ) & password_letters2_10 ,
        & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters_Digit , shifr_letters_count_Digit ) ;
      fputs ( ( localerus ?
        "из строки10 во внутренний пароль = " :
        "from string10 to internal password = " ) , stderr ) ;
      shifr_number_princ  ( v2 ) ( & password2 . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;

    }
    break ;
  case  3 :
    { shifr_number_priv_type ( v3 ) password2 ;

      shifr_string_to_password_templ  ( v3 ) ( main_shifrp ,
        ( shifr_strvcp  ) & main_shifrp -> password_letters3 ,
        & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters , shifr_letters_count ) ;
      fputs ( ( localerus ?
        "из строки95 во внутренний пароль = " :
        "from string95 to internal password = " ) , stderr ) ;
      shifr_number_princ  ( v3 ) ( & password2 . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;

      shifr_string_to_password_templ  ( v3 ) ( main_shifrp ,
        ( shifr_strvcp  ) & password_letters3_62  ,
        & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters62 , shifr_letters_count62 ) ;
      fputs ( ( localerus ?
        "из строки62 во внутренний пароль = " :
        "from string62 to internal password = " ) , stderr ) ;
      shifr_number_princ  ( v3 ) ( & password2 . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;

      shifr_string_to_password_templ  ( v3 ) ( main_shifrp ,
        ( shifr_strvcp  ) & password_letters3_52  ,
        & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters52 , shifr_letters_count52 ) ;
      fputs ( ( localerus ?
        "из строки52 во внутренний пароль = " :
        "from string52 to internal password = " ) , stderr ) ;
      shifr_number_princ  ( v3 ) ( & password2 . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;

      shifr_string_to_password_templ  ( v3 ) ( main_shifrp ,
        ( shifr_strvcp  ) & password_letters3_26 ,
        & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters4 , shifr_letters_count4 ) ;
      fputs ( ( localerus ?
        "из строки26 во внутренний пароль = " :
        "from string26 to internal password = " ) , stderr ) ;
      shifr_number_princ  ( v3 ) ( & password2 . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;

      shifr_string_to_password_templ  ( v3 ) ( main_shifrp ,
        ( shifr_strvcp  ) & password_letters3_10 ,
        & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters_Digit , shifr_letters_count_Digit ) ;
      fputs ( ( localerus ?
        "из строки10 во внутренний пароль = " :
        "from string10 to internal password = " ) , stderr ) ;
      shifr_number_princ  ( v3 ) ( & password2 . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;

    }
    break ;
  default :
    fprintf ( stderr  , ( localerus ? "неизвестная версия %d\n" : "unknown version %d\n" ) ,
      main_shifrp -> use_version ) ;
    main_shifrp -> string_exception  = ( localerus ?
      ( shifr_strcp ) & "неизвестная версия" :
      ( shifr_strcp ) & "unknown version" ) ;
    longjmp ( main_shifrp -> jump , 1 ) ;
  }
  shifr_memsetv ( password_letters2_62  , shifr_memsetv_default_byte ,
    sizeof  ( password_letters2_62  ) ) ;
  shifr_memsetv ( password_letters3_62  , shifr_memsetv_default_byte ,
    sizeof  ( password_letters3_62  ) ) ;
  shifr_memsetv ( password_letters2_52  , shifr_memsetv_default_byte ,
    sizeof  ( password_letters2_52  ) ) ;
  shifr_memsetv ( password_letters3_52  , shifr_memsetv_default_byte ,
    sizeof  ( password_letters3_52  ) ) ;
  shifr_memsetv ( password_letters2_26  , shifr_memsetv_default_byte ,
    sizeof  ( password_letters2_26  ) ) ;
  shifr_memsetv ( password_letters3_26  , shifr_memsetv_default_byte ,
    sizeof  ( password_letters3_26  ) ) ;
  shifr_memsetv ( password_letters2_10  , shifr_memsetv_default_byte ,
    sizeof  ( password_letters2_10  ) ) ;
  shifr_memsetv ( password_letters3_10  , shifr_memsetv_default_byte ,
    sizeof  ( password_letters3_10  ) ) ;
# else // not SHIFR_DEBUG
  switch  ( main_shifrp -> use_version ) {
  case  2 :
    switch  ( main_shifrp -> password_alphabet  ) {
    case  shifr_letters_count :
      shifr_password_to_string_templ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub ,
        & main_shifrp -> password_letters2 , & main_shifrp -> letters ,
        shifr_letters_count ) ;
      break ;
    case  shifr_letters_count62  :
      shifr_password_to_string_templ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub ,
        & main_shifrp -> password_letters2 , & main_shifrp -> letters62 ,
        shifr_letters_count62 ) ;
      break ;
    case  shifr_letters_count52  :
      shifr_password_to_string_templ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub ,
        & main_shifrp -> password_letters2 , & main_shifrp -> letters52 ,
        shifr_letters_count52 ) ;
      break ;
    case  shifr_letters_count_Digit  :
      shifr_password_to_string_templ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub ,
        & main_shifrp -> password_letters2 , & main_shifrp -> letters_Digit ,
        shifr_letters_count_Digit ) ;
      break ;
    case  shifr_letters_count4  :
      shifr_password_to_string_templ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub ,
        & main_shifrp -> password_letters2 , & main_shifrp -> letters4 ,
        shifr_letters_count4 ) ;
      break ;
    default :
      main_shifrp -> string_exception  = ( localerus ?
        ( shifr_strcp ) & "неизвестный алфавит пароля" :
        ( shifr_strcp ) & "unknown password alphabet" ) ;
      longjmp ( main_shifrp -> jump , 1 ) ;
    }
    puts  ( ( char * ) & ( main_shifrp -> password_letters2 [ 0 ] ) ) ;
    break ;
  case  3 :
    switch  ( main_shifrp -> password_alphabet  ) {
    case  shifr_letters_count :
      shifr_password_to_string_templ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub ,
        & main_shifrp -> password_letters3 , & main_shifrp -> letters ,
        shifr_letters_count ) ;
      break ;
    case  shifr_letters_count62  :
      shifr_password_to_string_templ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub ,
        & main_shifrp -> password_letters3 , & main_shifrp -> letters62 ,
        shifr_letters_count62 ) ;
      break ;
    case  shifr_letters_count52  :
      shifr_password_to_string_templ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub ,
        & main_shifrp -> password_letters3 , & main_shifrp -> letters52 ,
        shifr_letters_count52 ) ;
      break ;
    case  shifr_letters_count_Digit  :
      shifr_password_to_string_templ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub ,
        & main_shifrp -> password_letters3 , & main_shifrp -> letters_Digit ,
        shifr_letters_count_Digit ) ;
      break ;
    case  shifr_letters_count4  :
      shifr_password_to_string_templ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub ,
        & main_shifrp -> password_letters3 , & main_shifrp -> letters4 ,
        shifr_letters_count4 ) ;
      break ;
    default :
      main_shifrp -> string_exception  = ( localerus ?
        ( shifr_strcp ) & "неизвестный алфавит пароля" :
        ( shifr_strcp ) & "unknown password alphabet" ) ;
      longjmp ( main_shifrp -> jump , 1 ) ;
    }
    puts  ( ( char * ) & ( main_shifrp -> password_letters3 [ 0 ] ) ) ;
    break ;
  default :
    fprintf ( stderr , ( localerus ?
      "показать пароль : неопознанная версия : \'%d\'\n" :
      "show password : unrecognized version : \'%d\'\n" ) ,
      main_shifrp -> use_version ) ;
    main_shifrp -> string_exception  = ( localerus ?
      ( shifr_strcp ) & "показать пароль : неопознанная версия" :
      ( shifr_strcp ) & "show password : unrecognized version" ) ;
    longjmp ( main_shifrp -> jump  , 1 ) ;
  }
# endif // SHIFR_DEBUG
  shifr_memsetv ( main_shifrp -> password_letters2  , shifr_memsetv_default_byte ,
    sizeof  ( main_shifrp -> password_letters2  ) ) ;
  shifr_memsetv ( main_shifrp -> password_letters3  , shifr_memsetv_default_byte ,
    sizeof  ( main_shifrp -> password_letters3  ) ) ;
}

int shifr_show_help ( t_ns_shifr  const * const main_shifrp ) {
  bool  const localerus = main_shifrp -> localerus ;
  puts ( localerus ?
    "Шифр ©2020-3 Глебов А.Н.\n"
    "Симметричное поточное шифрование с 'солью'.\n"
    "'Соль' генерируется постоянно, что даёт хорошую стойкость.\n"
    "Размер данных увеличивается в два раза. "
    "В три раза в текстовом режиме.\n"
    "Нет диагностики неправильного пароля.\n"
    "Синтаксис : shifr [параметры]" :
    "Shifr ©2020-3 Glebe A.N.\n"
    "Symmetric stream encryption with 'salt'.\n"
    "'Salt' is constantly generated, which gives good durability.\n"
    "Data size doubles. Tripled in text mode.\n"
    "There is no diagnosis of the wrong password.\n"
    "Syntax : shifr [options]" ) ;
  puts  ( localerus ?
    "Параметры :" :
    "Options :"  ) ;
  puts  ( localerus ?
    "  --ген-пар или\n  --gen-pas\tгенерировать пароль" :
    "  --gen-pas\tpassword generate" );
  puts  ( localerus ?
    "  --зашифр или\n  --encrypt\tзашифровать\t(по-умолчанию)" :
    "  --encrypt\t(by default)" );
  puts  ( localerus ?
    "  --расшифр или\n  --decrypt\tрасшифровать" :
    "  --decrypt" );
  puts  ( localerus ?
    "  --пар или\n  --pas 'строка_пароля'\tиспользовать данный пароль" :
    "  --pas 'password_string'\tuse this password" ) ;
  puts  ( localerus ?
    "  --пар-путь или\n  --pas-path 'путь_к_файлу_с_паролем'\t"
    "использовать пароль в файле" :
    "  --pas-path 'path_to_password_file'\tuse password in file" );
  puts  ( localerus ?
    "  --вход или < или \n  --input 'имя_файла'\tчитать из файла "
    "(без данной опции"
    " читаются данные со стандартного входа)" :
    "  --input or < 'file_name'\tread from file (without this option data "
    "reads from standard input)" ) ;
  puts  ( localerus ?
    "  --выход или > или \n  --output 'имя_файла'\tзаписывать в файл "
    "(без данной опции записываются данные в стандартный выход)" :
    "  --output or > 'file_name'\twrite to file (without this option "
    "data writes to standard output)" ) ;
  puts  ( localerus ?
    "  --текст или\n  --text\tшифрованный файл записан текстом ascii" :
    "  --text\tencrypted file written in ascii text" ) ;
  puts  ( localerus ?
    "  --2\tиспользовать двух битное шифрование, ключ = 45 бит ( 6 - 14 букв ). ( по-умолчанию )" :
    "  --2\tusing two bit encryption, key = 45 bits ( 6 - 14 letters )."
    " ( by default )" ) ;
  puts  ( localerus ?
    "  --3\tиспользовать трёх битное шифрование, ключ = 296 бит ( 45 - 90 букв )." :
    "  --3\tusing three bit encryption, key = 296 bits ( 45 - 90 letters )."  ) ;
  puts  ( "  --rus или\n  --рус\tрусский язык"  ) ;
  puts  ( "  --анг or\n  --eng\tenglish language" ) ;
  fputs  ( localerus ?
    "Буквы в пароле (алфавит):\n  --а95 или\n  --a95\t\'" :
    "Letters in password (alphabet):\n  --a95\t\'" , stdout ) ;
  { char const * cj = & ( main_shifrp -> letters [ 0 ] ) ;
    do {
      fputc ( * cj  , stdout  ) ;
      ++ cj ;
    } while ( cj not_eq ( & ( main_shifrp -> letters [ shifr_letters_count ] ) ) ) ;
  }

  fputs ( ( main_shifrp -> localerus ?
    "\'\n  --а62 или\n  --a62\t\'" :
    "\'\n  --a62\t\'" ) , stdout  ) ;
  { char const * cj = & ( main_shifrp -> letters62 [ 0 ] ) ;
    do {
      fputc ( * cj  , stdout  ) ;
      ++ cj ;
    } while ( cj not_eq ( & ( main_shifrp -> letters62 [ shifr_letters_count62 ] ) ) ) ;
  }

  fputs ( ( main_shifrp -> localerus ?
    "\'\t(по умолчанию)\n" :
    "\'\t(by default)\n"  ) , stdout  ) ;

  fputs ( ( main_shifrp -> localerus ?
    "  --а52 или\n  --a52\t\'" :
    "  --a52\t\'" ) , stdout  ) ;
  { char const * cj = & ( main_shifrp -> letters52 [ 0 ] ) ;
    do {
      fputc ( * cj  , stdout  ) ;
      ++ cj ;
    } while ( cj not_eq ( & ( main_shifrp -> letters52 [ shifr_letters_count52 ] ) ) ) ;
  }

  fputs ( ( main_shifrp -> localerus ?
    "\'\n  --а26 или\n  --a26\t\'" :
    "\'\n  --a26\t\'" ) , stdout  ) ;
  { char const * cj = & ( main_shifrp -> letters4 [ 0 ] ) ;
    do {
      fputc ( * cj  , stdout  ) ;
      ++ cj ;
    } while ( cj not_eq ( & ( main_shifrp -> letters4 [ shifr_letters_count4 ] ) ) ) ;
  }
  fputs ( "\'\n" , stdout  ) ;
  fputs ( ( localerus ?
    "  --a10 --adig или\n  --а10\t\'" :
    "  --a10 --adig\t\'" ) , stdout  ) ;
  { char const * cj = & ( main_shifrp -> letters_Digit [ 0 ] ) ;
    do {
      fputc ( * cj  , stdout  ) ;
      ++ cj ;
    } while ( cj not_eq ( & ( main_shifrp -> letters_Digit [ shifr_letters_count_Digit ] ) ) ) ;
  }
  fputs ( "\'\n" , stdout  ) ;
  puts  ( localerus ?
    "Пример использования :"  :
    "Usage example"  ) ;
  puts  ( localerus ?
    "  $ ./shifr --ген-пар > psw"  :
    "  $ ./shifr --gen-pas > psw"  ) ;
  puts  (
    "  $ cat psw\n"
    "  kz8359K3"  ) ;
  puts  ( localerus ?
    "  $ ./shifr --пар-путь 'psw' > test.shi --текст"  :
    "  $ ./shifr --pas-path 'psw' > test.shi --text"  ) ;
  puts  ( localerus ?
    "  2+2=5 (Нажимаем Enter,Ctrl+D)" :
    "  2+2=5 (Press Enter,Ctrl+D)" ) ;
  puts  (
    "  $ cat test.shi\n"
    "  cUdDZClDEALaFVYMmf" ) ;
  puts( localerus ?
    "  $ ./shifr --пар-путь 'psw' < test.shi --текст --расшифр" :
    "  $ ./shifr --pas-path 'psw' < test.shi --text --decrypt" ) ;
  puts  ( "  2+2=5" ) ;
  return 0 ;
}

# ifdef SHIFR_DEBUG

# include <sys/time.h> // gettimeofday

shifr_timestamp_t get_timestamp ( void ) {
  struct timeval now  ;
  gettimeofday (  & now , ( struct timezone * ) 0 ) ;
  return  now . tv_usec + ( shifr_timestamp_t ) now . tv_sec * 1000000LL  ;
}

# endif // SHIFR_DEBUG

void  shifr_init  ( t_ns_shifr  * const ns_shifrp ) {
  ns_shifrp ->  use_version = 2 ;
  ns_shifrp ->  flagtext  = false ;
  ns_shifrp ->  password_alphabet = shifr_letters_count62 ;
  { char * j = & ( ns_shifrp -> letters [ 0 ] ) ;
    uint8_t i = ' ' ;
    do {
      ( * j ) = uint8_cast_char ( i ) ;
      ++ i  ;
      ++ j  ;
    } while ( i <= '~' ) ;
  }
  // 0x30 '0' - 0x39 '9' , 0x41 'A' - 0x5a 'Z' , 0x61 'a' - 0x7a 'z'
  { char * j = & ( ns_shifrp -> letters62 [ 0 ] ) ;
    { uint8_t i = '0' ;
      do {
        ( * j ) = uint8_cast_char ( i ) ;
        ++ i  ;
        ++ j  ;
      } while ( i <= '9' ) ;
    }
    { uint8_t i = 'A' ;
      do {
        ( * j ) = uint8_cast_char ( i ) ;
        ++ i  ;
        ++ j  ;
      } while ( i <= 'Z'  ) ;
    }
    { uint8_t i = 'a' ;
      do {
        ( * j ) = uint8_cast_char ( i ) ;
        ++ i  ;
        ++ j  ;
      } while ( i <= 'z'  ) ;
    }
  }
  // 0x41 'A' - 0x5a 'Z' , 0x61 'a' - 0x7a 'z'
  { char * j = & ( ns_shifrp -> letters52 [ 0 ] ) ;
    { uint8_t i = 'A' ;
      do {
        ( * j ) = uint8_cast_char ( i ) ;
        ++ i  ;
        ++ j  ;
      } while ( i <= 'Z'  ) ;
    }
    { uint8_t i = 'a' ;
      do {
        ( * j ) = uint8_cast_char ( i ) ;
        ++ i  ;
        ++ j  ;
      } while ( i <= 'z'  ) ;
    }
  }
  { char * j = & ( ns_shifrp -> letters_Digit  [ 0 ] ) ;
    uint8_t i = '0' ;
    do {
      ( * j ) = uint8_cast_char ( i ) ;
      ++ i  ;
      ++ j  ;
    } while ( i <= '9' ) ;
  }
  { char * j = & ( ns_shifrp -> letters4  [ 0 ] ) ;
    uint8_t i = 'a' ;
    do {
      ( * j ) = uint8_cast_char ( i ) ;
      ++ i  ;
      ++ j  ;
    } while ( i <= 'z' ) ;
  }
  ns_shifrp ->  filebuffrom . file  = stdin ;
  ns_shifrp ->  filebufto . file  = stdout  ;
  shifr_salt_init ( ns_shifrp ) ;
}

// from stdin get password string -> make big number -> tables shifr deshi
void  shifr_enter_password ( t_ns_shifr * const ns_shifrp ) {
  switch ( ns_shifrp -> use_version ) {
  case  3 :
    shifr_enter_password_name  ( v3  ) ( ns_shifrp ) ;
    break ;
  case 2 :
    shifr_enter_password_name  ( v2  ) ( ns_shifrp ) ;
    break ;
  default :
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      "enter_password:Неизвестная версия %d\n" :
      "enter_password:Unknown version %d\n" ) , ns_shifrp -> use_version  ) ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & "enter_password:Неизвестная версия" :
      ( shifr_strcp ) & "enter_password:Unknown version" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
  shifr_password_load_uni ( ns_shifrp ) ;
}

// generate big number as password to raspr.pass
//  + create tables shifr deshi
void  shifr_generate_password ( t_ns_shifr * const ns_shifrp ) {
  switch  ( ns_shifrp -> use_version  ) {
  case  2 :
    shifr_generate_dices ( v2 ) ( ns_shifrp ) ;
    shifr_dices_to_number ( v2 ) ( ns_shifrp ) ;
# ifdef SHIFR_DEBUG
    fputs ( ( ns_shifrp -> localerus ?
      "generate_password:внутренний пароль = " :
      "generate_password:internal password = " ) , stderr ) ;
    shifr_number_princ  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
      stderr  ) ;
    fputs ( "\n" , stderr ) ;
# endif
    break ;
  case 3 :
    shifr_generate_dices ( v3 ) ( ns_shifrp ) ;
    shifr_dices_to_number ( v3 ) ( ns_shifrp ) ;
# ifdef SHIFR_DEBUG
    fputs ( ( ns_shifrp -> localerus ?
      "generate_password:внутренний пароль = " :
      "generate_password:internal password = " ) , stderr ) ;
    shifr_number_princ  ( v3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
      stderr  ) ;
    fputs ( "\n" , stderr ) ;
# endif
    break ;
  default :
    fprintf ( stderr , ( ns_shifrp -> localerus ?
      "generate_password:неопознанная версия : \'%d\'\n" :
      "generate_password:unrecognized version : \'%d\'\n" ) ,
      ns_shifrp -> use_version ) ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & "generate_password:неопознанная версия" :
      ( shifr_strcp ) & "generate_password:unrecognized version" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
}
# include "inlinepri.h"
