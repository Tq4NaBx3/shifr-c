// Шифр ©2020-3 Глебов А.Н.
// Shifr ©2020-3 Glebe A.N.

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
# include "inline.h"

# define  shifr_number_def_set0( N , D ) \
  void shifr_number_set0  ( N ) ( shifr_number_type  ( N ) * const np ) { \
    memset  ( & ( shifr_number_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) , 0 ,  \
      D ) ; \
  }

shifr_number_def_set0 ( v2 , shifr_number_size2 )
shifr_number_def_set0 ( v3 , shifr_number_size3 )

# define  shifr_number_def_mul_byte(  N , D ) \
void  shifr_number_mul_byte ( N ) ( shifr_number_type ( N ) * const np  , \
  uint8_t const byte ) {  \
  if ( byte == 0 ) {  \
    shifr_number_set0 ( N ) ( np ) ; \
    return  ; \
  } \
  if ( byte == 1 )  \
    return ; \
  uint8_t per = 0 ; \
  { uint8_t i = 0 ; \
    do { \
      uint16_t const x = int_cast_uint16 ( uint8_cast_uint16 ( \
        shifr_number_elt_copy ( N ) ( np , i ) ) * \
        uint8_cast_uint16 ( byte ) + uint8_cast_uint16 ( per ) ) ; \
      shifr_number_pub_to_priv ( N ) ( np ) -> arr [ i ] =  \
        int_cast_uint8 ( x bitand 0xff ) ; \
      per = int_cast_uint8 ( x >>  8 ) ; \
      ++  i ; \
    } while ( i < D ) ; \
  } \
}

shifr_number_def_mul_byte ( v2 , shifr_number_size2 )
shifr_number_def_mul_byte ( v3 , shifr_number_size3 )

# include "define.h"

# ifdef SHIFR_DEBUG
void  shifr_printarr  ( shifr_strcp const  name , shifr_arrcp const p ,
  size_t const arrsize , FILE * const f ) {
  fprintf  ( f  , "%s = [ " , * name  ) ;
  uint8_t const * i = & ( ( * p ) [ 0 ] ) ;
  do {
    fprintf  ( f  , "%hhx " , * i ) ; 
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
void  shifr_password  ##  N ##  _to_string_templ ( \
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

// читаю 6 бит
// 6 bits reads
static  inline  bool  isEOBstreambuf_read6bits ( t_ns_shifr * const ns_shifrp ,
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
      // читаем одну букву ';'-'z' -> декодируем в шесть бит
      // reads one letter ';'-'z' -> decode to six bits
    } while ( ( buf < char_cast_uint8 ( ';' ) ) or
      ( buf > char_cast_uint8 ( 'z' ) ) ) ;
    ( * encrypteddata ) = letter_to_bits6 ( uint8_cast_char ( buf ) ) ;
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

uint8_t shifr_flush ( t_ns_shifr  * const ns_shifrp ,
  shifr_arrps const output  ) {
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
    ns_shifrp ->  string_exception  = ( shifr_strcp ) &
      "shifr_flush : unknown version" ;
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
uint8_t shifr_encrypt2_flush  ( t_ns_shifr * const ns_shifrp ,
  shifr_arrps const output ) {
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
  if  ( ns_shifrp -> bitscount ==  1 )
    ns_shifrp -> secretdata [ 0 ] = ns_shifrp -> secretdata [ 3 ] ;
  else
    ns_shifrp -> secretdata [ 0 ] = ns_shifrp -> secretdata [ 2 ] ;
  shifr_datasalt3 ( ns_shifrp , ( shifr_arrcp ) & ns_shifrp -> secretdata ,
    & ns_shifrp -> secretdatasalt , 1 )  ;
  uint8_t secretdatasaltsize  = 1 ;  
  // после подсоления, данные переворачиваем предыдущим xor-ом
  // after settling in, we turn the data over with the previous xor
  data_xor3 ( & ns_shifrp -> old_last_data , & ns_shifrp -> old_last_salt ,
    & ns_shifrp -> secretdatasalt , secretdatasaltsize )  ;
  uint8_t encrypteddata [ 3 ] ;
  shifr_crypt_decrypt ( & ns_shifrp -> secretdatasalt ,
    ( shifr_arrcp ) & ns_shifrp  -> shifr3 , & encrypteddata ,
    secretdatasaltsize ) ;
  
  size_t  writes  = 0 ;
  shifr_streambuf_write3 ( ns_shifrp , & ns_shifrp -> filebufto ,
    ( uint8_t const ( * ) [ 3 ] ) & encrypteddata ,
    secretdatasaltsize  , ns_shifrp  -> flagtext , & output_buffer , & writes ,
    arrpsp . s )  ;
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
shifr_size_io shifr_encrypt2  ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcps const input , shifr_arrps const output  ) {
  uint8_t const * restrict  input_buffer = & ( ( * input . cp  ) [ 0 ] ) ;
  uint8_t * restrict  output_buffer = & ( ( * output  . p ) [ 0 ] ) ;
  size_t  reads = 0 ;
  size_t  writes  = 0 ;
  while ( reads < input . s and writes + 4 <= output . s ) {
    char const  buf = uint8_cast_char ( * input_buffer ) ;
    ++  input_buffer  ;
    ++  reads ;
    uint8_t const secretdata  [ 4 ] = { [ 0 ]  = buf  bitand 0x3 ,
      [ 1 ] = ( buf >>  2 ) bitand 0x3 , [ 2 ] = ( buf >>  4 ) bitand 0x3 ,
      [ 3 ] = ( buf >>  6 ) bitand 0x3 } ;
    uint8_t secretdatasalt  [ 4 ] ;
    shifr_datasalt2 ( ns_shifrp , & secretdata , & secretdatasalt , 4 )  ;
    // после подсоления, данные переворачиваем предыдущим xor-ом
    // after settling in, we turn the data over with the previous xor
    shifr_data_xor2 ( ns_shifrp , & secretdatasalt , 4 )  ;
    uint8_t encrypteddata [ 4 ] ;
    shifr_crypt_decrypt ( & secretdatasalt , ( shifr_arrcp ) & ns_shifrp  ->
      shifr2 , & encrypteddata , 4 ) ;
// 2^16 ^ 1/3 = 40.32
// 2^16 % 40 = 0 .. 39
// 2^16 / 40 = 1638.4
// 1639 ^ 1/2 = 40.48
// 1639 % 40 = 0 .. 39
// 1639 / 40 = 40.97
// делаем make [0] % 40 , [1] % 40 , [2] % 41
// 'R' = 82 .. 'z' = 122
    if  ( ns_shifrp  -> flagtext  ) {
      uint16_t  buf16 = int_cast_uint16 (
        ( int_cast_uint16 ( encrypteddata [ 0 ] bitand  0xf ) ) bitor
        ( (int_cast_uint16( encrypteddata [ 1 ] bitand 0xf )) << 4  )  bitor
        ( (int_cast_uint16( encrypteddata [ 2 ] bitand 0xf )) << 8  )  bitor
        ( (int_cast_uint16( encrypteddata [ 3 ] bitand 0xf )) << 12  )) ;
      char buf3 [ 4 ] ;
      buf3 [ 0 ] = int_cast_char ( 'R' + ( buf16 % 40 ) ) ;
      buf16 /= 40 ;
      buf3 [ 1 ] = int_cast_char ( 'R' + ( buf16 % 40 ) ) ;
      buf16 /= 40 ;
      buf3 [ 2 ] = int_cast_char ( 'R' + buf16 ) ;
      ns_shifrp  -> charcount += 3 ;
      if ( ns_shifrp  -> charcount == 60 )  {
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
      char buf2 [ 2 ] = {
        [ 0 ] = int_cast_char ( ( int_cast_uint16 ( encrypteddata [ 0 ] &
          0xf ) )
          bitor ( (int_cast_uint16( encrypteddata [ 1 ] & 0xf )) << 4  ) ) ,
        [ 1 ] = int_cast_char ( ( int_cast_uint16( encrypteddata [ 2 ] & 0xf
          ) ) bitor
          ( ( int_cast_uint16 ( encrypteddata [ 3 ] & 0xf )) << 4 ) ) } ;
      memcpy  ( output_buffer , & ( buf2 [ 0 ] )  , 2 ) ;
      writes  +=  2 ;
      output_buffer +=  2 ;
    }
  }
  return  ( shifr_size_io ) { .i  = reads , .o  = writes  } ;
}

// returns size loads & writes
shifr_size_io shifr_encrypt3  ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcps const input , shifr_arrps const output  ) {
  uint8_t secretdatasaltsize  ;
  uint8_t encrypteddata [ 3 ] ;
  size_t  reads = 0 ;
  size_t  writes  = 0 ;
  uint8_t const * restrict  input_buffer = &  ( ( * input . cp  ) [ 0 ] ) ;
  uint8_t * restrict  output_buffer = & ( ( * output  . p ) [ 0 ] ) ;
  while ( reads < input . s and writes < output . s ) {
    unsigned  char buf = ( * input_buffer ) ;
    ++  input_buffer  ;
    ++  reads ;
    switch  ( ns_shifrp -> bitscount  ) {
    case  0 :
      // <= [ [1 0] [2 1 0] [2 1 0] ]
      ( ns_shifrp -> secretdata ) [ 0 ]  = buf  bitand 0x7 ;
      ( ns_shifrp -> secretdata ) [ 1 ] = ( buf >>  3 ) bitand 0x7 ;
      ( ns_shifrp -> secretdata ) [ 2 ] = buf >>  6 ;
      ns_shifrp -> bitscount  = 2 ; // 0 + 8 - 6
      secretdatasaltsize  = 2 ;
      break ;
    case  1 : 
      // <= [ [2 1 0] [2 1 0] [2 1] ] <= [ [0]
      ( ns_shifrp -> secretdata ) [ 0 ] = int_cast_uint8 (
        ( ns_shifrp -> secretdata ) [ 3 ] bitor
        ( ( buf  bitand 0x3 ) <<  1 ) ) ;
      ( ns_shifrp -> secretdata ) [ 1 ] = ( buf >>  2 ) bitand 0x7 ;
      ( ns_shifrp -> secretdata ) [ 2 ] = buf >>  5 ;
      ns_shifrp -> bitscount  = 0 ;   // 1 + 8 - 9
      secretdatasaltsize  = 3 ;
      break ;
    case  2 :
      // <= [ [0] [2 1 0] [2 1 0] [2] ] <= [ [1 0] ..
      ( ns_shifrp -> secretdata ) [ 0 ] = int_cast_uint8 (
        ( ns_shifrp -> secretdata ) [ 2 ] bitor
        ( ( buf  bitand 0x1 ) <<  2 ) ) ;
      ( ns_shifrp -> secretdata ) [ 1 ] = ( buf >>  1 ) bitand 0x7 ;
      ( ns_shifrp -> secretdata ) [ 2 ] = ( buf >>  4 ) bitand 0x7 ;
      ( ns_shifrp -> secretdata ) [ 3 ] = buf >>  7 ;
      ns_shifrp -> bitscount  = 1 ; // 2 + 8 - 9
      secretdatasaltsize  = 3 ;
      break ;
    default :
      fprintf ( stderr  , ( ns_shifrp -> localerus ?
        "неожиданное значение bitscount = %d\n":
        "unexpected value bitscount = %d\n" ) , ns_shifrp -> bitscount ) ;
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ? 
        ( shifr_strcp ) & "неожиданное значение bitscount" :
        ( shifr_strcp ) & "unexpected value bitscount" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; 
    } // switch  ( ns_shifrp -> bitscount  )
    shifr_datasalt3 ( ns_shifrp , ( shifr_arrcp ) &
      ( ns_shifrp -> secretdata ) , & ns_shifrp -> secretdatasalt ,
      secretdatasaltsize )  ;
    // после подсоления, данные переворачиваем предыдущим ксором
    // after salting in, we turn the data over with the previous xor
    data_xor3 ( & ns_shifrp -> old_last_data , & ns_shifrp -> old_last_salt ,
      & ns_shifrp -> secretdatasalt , secretdatasaltsize ) ;
    shifr_crypt_decrypt ( & ns_shifrp -> secretdatasalt ,
      ( shifr_arrcp ) & ns_shifrp  -> shifr3 , & encrypteddata ,
      secretdatasaltsize ) ;
    shifr_streambuf_write3 ( ns_shifrp , & ns_shifrp -> filebufto ,
      ( uint8_t const ( * ) [ 3 ] ) & encrypteddata ,
      secretdatasaltsize , ns_shifrp  -> flagtext , & output_buffer ,
      & writes , output . s ) ;
  } // while
  return ( shifr_size_io ) { .i  = reads , .o  = writes  }  ;
}

// returns size loads & writes
shifr_size_io  shifr_decrypt2  ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcps const input , shifr_arrps const output  ) {
  uint8_t const * restrict  input_buffer = &  ( ( * input . cp  ) [ 0 ] ) ;
  uint8_t * restrict  output_buffer = & ( ( * output  . p ) [ 0 ] ) ;
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
// делаем make [0] % 40 , [1] % 40 , [2] % 41
// 'R' = 82 .. 'z' = 122
      // читаем три буквы ' a 1 b' -> декодируем в два байта "XY"
      // reads three letters ' a 1 b' -> decode to two bytes "XY"
      do {
        do {
          if ( reads >= input . s or writes >= output . s )
            goto Exit ;
          ( ns_shifrp  -> buf2 ) [ ns_shifrp  -> buf2index ] =
            uint8_cast_char ( * input_buffer ) ;
          ++  input_buffer  ;
          ++  reads ;
        } while ( ( ns_shifrp  -> buf2 ) [ ns_shifrp  -> buf2index ] < 'R' or
          ( ns_shifrp  -> buf2 ) [ ns_shifrp  -> buf2index ] > 'z' ) ;
        ++ ( ns_shifrp  -> buf2index ) ;
      } while ( ns_shifrp  -> buf2index < 3 ) ;
      // next letters begins with zero index
      // следующие буквы начинают с нулевого индекса
      ns_shifrp  -> buf2index = 0 ;
      uint16_t u16 = uint_cast_uint16 (
        ( int_cast_uint16 ( ( ns_shifrp  -> buf2 ) [ 0 ] - 'R' ) ) +
        40U * ( ( int_cast_uint16 ( ( ns_shifrp  -> buf2 ) [ 1 ] - 'R' ) ) +
        40U * ( int_cast_uint16 ( ( ns_shifrp  -> buf2 ) [ 2 ] - 'R' ) ) ) ) ;
      buf [ 0 ] = uint16_cast_char ( u16 bitand 0xff ) ;
      buf [ 1 ] = uint16_cast_char ( u16 >> 8  ) ;
    } else {  // flagtext
      if ( reads + 1 >= input . s )
        goto Exit ;
      buf [ 0 ] = uint8_cast_char ( * input_buffer ) ;
      ++  input_buffer  ;
      ++  reads ;
      buf [ 1 ] = uint8_cast_char ( * input_buffer ) ;
      ++  input_buffer  ;
      ++  reads ;
    } // flag digit
    uint8_t secretdata  [ 4 ] = { [ 0 ] = buf [ 0 ] bitand  0xf ,
      [ 1 ] = ( buf [ 0 ] >>  4 ) bitand  0xf ,
      [ 2 ] = buf [ 1 ] bitand  0xf ,
      [ 3 ] = ( buf [ 1 ] >>  4 ) bitand  0xf  } ;
    uint8_t decrypteddata [ 4 ] ;
    shifr_decrypt_salt2 ( & secretdata , ( shifr_arrcp ) & ( ns_shifrp  ->
        deshi2 ) , & decrypteddata , 4 , & ns_shifrp  -> old_last_salt ,
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

shifr_size_io shifr_decrypt3 ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcps const input , shifr_arrps const output ) {
  uint8_t const * restrict  input_buffer = &  ( ( * input . cp  ) [ 0 ] ) ;
  uint8_t * restrict  output_buffer = & ( ( * output  . p ) [ 0 ] ) ;
  size_t  reads = 0 ;
  size_t  writes  = 0 ;
  uint8_t secretdata [ 1 ] ;
  while ( ( reads < input . s or
      ( ns_shifrp -> filebuffrom . bufbitsize ) ==  6 ) and
    writes  < output  . s ) {
    if ( isEOBstreambuf_read6bits ( ns_shifrp ,
      & ( secretdata [ 0 ] ) , & reads , & input_buffer , input . s ) )
      break ;
    uint8_t decrypteddata [ 1 ] ;
    shifr_decrypt_salt3 ( & secretdata , ( shifr_arrcp ) &
      ns_shifrp  -> deshi3 , & decrypteddata , 1 ,
      & ns_shifrp  -> old_last_salt , & ns_shifrp  -> old_last_data ) ;
    shifr_streambuf_write3bits ( ns_shifrp , decrypteddata [ 0 ] , &
      output_buffer , & writes ) ;
  } // while
  return  ( shifr_size_io ) { . i  = reads , .  o  = writes  } ;
}

// ! to remove , make random 0..16!-1
// generate array raspr2.dice
// inits array [ 0..15 , 0..14 , ... , 0..2 , 0..1 ]
void  shifr_generate_dices2 ( t_ns_shifr * const ns_shifrp ) {
  uint8_t * j = & ( ns_shifrp -> raspr2  . dice [ 0 ] ) ;
  uint8_t i  = 0x10 - 1 ; // 15
  do {
    ( * j ) = uint_cast_uint8 ( shifr_uirandfrto  ( ns_shifrp , 0 , i ) ) ;
    --  i ;
    ++  j ;
  } while ( i >= 1 ) ;
}

// ! to remove , make random 0..64!-1
// generate array raspr3.dice
// inits array [ 0..63 , 0..62 , ... , 0..2 , 0..1 ]
void  shifr_generate_dices3 ( t_ns_shifr * const ns_shifrp ) {
  uint8_t * j = & ( ns_shifrp -> raspr3  . dice [ 0 ] ) ;
  uint8_t i  = 0x40 - 1 ; // 63
  do {
    ( * j ) = uint_cast_uint8 ( shifr_uirandfrto  ( ns_shifrp , 0 , i ) ) ;
    -- i  ;
    ++ j  ;
  } while ( i >= 1 ) ;
}

// convert raspr2.dice as array to big number raspr2.pass
//  + create tables shifr deshi
// [ 0..15 , 0..14 , 0..13 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ]
// = x + y * 16 + z * 16 * 15 + ... + u * 16! / 2 / 3 + v * 16! / 2 =
// 0 .. 16!-1
void  shifr_dices_to_number2 ( t_ns_shifr * const ns_shifrp ) {
  shifr_number_set0 ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ) ;
  shifr_number_priv_type ( v2 ) mu  ;
  shifr_number_set_byte ( v2 ) ( & mu . pub , 1 ) ;
  uint8_t in = 0 ;
  do {
    { shifr_number_priv_type ( v2 ) mux = mu ;
      // re += dice [ in ] * mu ;
      shifr_number_mul_byte ( v2 ) ( & mux . pub ,
        ns_shifrp -> raspr2  . dice [ in ] ) ;
      shifr_number_add  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
        & mux . pub ) ;
    }
    //$mu *=  16 - $in ;
    shifr_number_mul_byte ( v2 ) ( & mu . pub ,
      int_cast_uint8 ( 0x10 - in ) ) ;
    ++  in ;
  } while ( in < 0x10 - 1 ) ;
  shifr_password_from_dice_uni  ( ns_shifrp ) ;
}

// convert raspr3.dice as array to big number raspr3.pass
//  + create tables shifr deshi
// [ 0..63 , 0..62 , 0..61 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ]
// = x + y * 64 + z * 64 * 63 + ... + u * 64! / 2 / 3 + v * 64! / 2 = 
// 0 .. 64!-1
void  shifr_dices_to_number3 ( t_ns_shifr * const ns_shifrp ) {
  shifr_number_set0 ( v3 ) ( & ns_shifrp -> raspr3  . pass . pub ) ;
  shifr_number_priv_type ( v3 ) mu  ;
  shifr_number_set_byte ( v3 ) ( & mu . pub , 1 ) ;
  uint8_t in = 0 ;
  do {
    { shifr_number_priv_type ( v3 ) mux = mu ;
      // re += dice [ in ] * mu ;
      shifr_number_mul_byte ( v3 ) (
        & mux . pub ,  ns_shifrp -> raspr3  . dice [ in ] ) ;
      shifr_number_add  ( v3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
        & mux . pub ) ;
    }
    //$mu *=  64 - $in ;
    shifr_number_mul_byte ( v3 ) ( & mu . pub ,
      int_cast_uint8 ( 0x40 - in ) ) ;
    ++  in ;
  } while ( in < 0x40 - 1 ) ;
  // reverse math .. dice [ i ] == cindex in _load
  shifr_password_from_dice_uni  ( ns_shifrp ) ;
}

# ifdef SHIFR_DEBUG

# define  shifr_number_def_princ( N , D ) \
void  shifr_number_princ  ( N ) ( \
  shifr_number_type ( N ) const * const np , FILE * const fs ) { \
  fputs ( "[ " , fs ) ; \
  uint8_t i = D - 1 ;  \
  do  { \
    fprintf ( fs  , "%x " , shifr_number_elt_copy ( N ) ( np , i ) ) ; \
    if ( ! i ) \
      break ; \
    --  i ; \
  } while ( true ) ; \
  fputs ( "]" , fs ) ; \
}

shifr_number_def_princ  ( v2 , shifr_number_size2 )
shifr_number_def_princ  ( v3 , shifr_number_size3 )

# endif // SHIFR_DEBUG

void  shifr_password_set_by_string ( t_ns_shifr * const ns_shifrp ,
  char const * const pswstr ) {
  switch ( ns_shifrp -> use_version ) {
  case  2 :
    strncpy ( charvolatilep_cast_charp ( &
      ns_shifrp  -> password_letters2 [ 0 ] ) , pswstr ,
      shifr_password_letters2size ) ;
    if ( ns_shifrp  -> password_letters2 [ shifr_password_letters2size - 1 ]
      != '\00' ) {
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) &
        "shifr_password_set_string : пароль очень длинный" :
        ( shifr_strcp ) & 
        "shifr_password_set_string : the password is very long" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ;
    }
    break ;
  case  3 :
    strncpy ( charvolatilep_cast_charp ( &
      ns_shifrp  -> password_letters3 [ 0 ] ) , pswstr ,
      shifr_password_letters3size ) ;
    if ( ns_shifrp  -> password_letters3 [ shifr_password_letters3size - 1 ]
      != '\00' ) {
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) & 
        "shifr_password_set_string : пароль очень длинный" :
        ( shifr_strcp ) & 
        "shifr_password_set_string : the password is very long" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ;
    }
    break ;
  default :
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      "shifr_password_set_string : неизвестная версия %d\n" :
      "shifr_password_set_string : unknown version %d\n" ) ,
      ns_shifrp -> use_version )  ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & "shifr_password_set_string : неизвестная версия" :
      ( shifr_strcp ) & "shifr_password_set_string : unknown version" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ;
  }
  shifr_string_to_password  ( ns_shifrp ) ;
}

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
    case  shifr_letters_count :
      shifr_string_to_password_templ  ( v2 ) ( ns_shifrp ,
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters2 ,
        & ns_shifrp -> raspr2  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters ,  shifr_letters_count ) ;
      break ;
    case  shifr_letters_count2  :
      shifr_string_to_password_templ  ( v2 ) ( ns_shifrp ,
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters2 ,
        & ns_shifrp -> raspr2  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters2 , shifr_letters_count2 ) ;
      break ;
    case  shifr_letters_count3  :
      shifr_string_to_password_templ  ( v2 ) ( ns_shifrp ,
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters2 ,
        & ns_shifrp -> raspr2  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters3 , shifr_letters_count3 ) ;
      break ;
    case  shifr_letters_count4  :
      shifr_string_to_password_templ  ( v2 ) ( ns_shifrp ,
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters2 ,
        & ns_shifrp -> raspr2  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters4 , shifr_letters_count4 ) ;
      break ;
    default :
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) &
        "string_to_password : версия алфавита не известна" :
        ( shifr_strcp ) & 
        "string_to_password : alphabet version is not known" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ;
    }
    break ;
  case 3 :
    switch  ( ns_shifrp -> password_alphabet  ) {
    case  shifr_letters_count :
      shifr_string_to_password_templ  ( v3 ) ( ns_shifrp ,
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters3 ,
        & ns_shifrp -> raspr3  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters ,  shifr_letters_count ) ;
      break ;
    case  shifr_letters_count2  :
      shifr_string_to_password_templ  ( v3 ) ( ns_shifrp , 
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters3 ,
        & ns_shifrp -> raspr3  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters2 , shifr_letters_count2 ) ;
      break ;
    case  shifr_letters_count3  :
      shifr_string_to_password_templ  ( v3 ) ( ns_shifrp , 
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters3 ,
        & ns_shifrp -> raspr3  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters3 , shifr_letters_count3 ) ;
      break ;
    case  shifr_letters_count4  :
      shifr_string_to_password_templ  ( v3 ) ( ns_shifrp , 
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters3 ,
        & ns_shifrp -> raspr3  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters4 , shifr_letters_count4 ) ;
      break ;
    default :
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) & 
        "string_to_password : версия алфавита не известна" :
        ( shifr_strcp ) & 
        "string_to_password : alphabet version is not known" ) ;
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
    shifr_password_load ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
      & ns_shifrp  -> shifr2 , & ns_shifrp  -> deshi2 ) ;
    break ;
  case 3 :
    shifr_password_load ( v3 ) ( & ns_shifrp -> raspr3  . pass . pub , 
      & ns_shifrp  -> shifr3 , & ns_shifrp  -> deshi3 ) ;
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
      & ns_shifrp  -> shifr2 , & ns_shifrp  -> deshi2 ) ;
    break ;
  case 3 :
    shifr_password_from_dice ( v3 ) ( ns_shifrp  -> raspr3 . dice , 
      & ns_shifrp  -> shifr3 , & ns_shifrp  -> deshi3 ) ;
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
    case  shifr_letters_count2  :
      shifr_password_to_string_templ  ( v2 ) (
        & ns_shifrp -> raspr2  . pass . pub ,
        & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters2 ,
        shifr_letters_count2 ) ;
      break ;
    case  shifr_letters_count3  :
      shifr_password_to_string_templ  ( v2 ) (
        & ns_shifrp -> raspr2  . pass . pub ,
        & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters3 ,
        shifr_letters_count3 ) ;
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
    case  shifr_letters_count2  :
      shifr_password_to_string_templ  ( v3 ) (
        & ns_shifrp -> raspr3  . pass . pub ,
        & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters2 ,
        shifr_letters_count2 ) ;
      break ;
    case  shifr_letters_count3  :
      shifr_password_to_string_templ  ( v3 ) (
        & ns_shifrp -> raspr3  . pass . pub ,
        & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters3 ,
        shifr_letters_count3 ) ;
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
  shifr_memsetv ( ns_shifrp ->  password_letters2 ,
    shifr_memsetv_default_byte ,
    sizeof  ( ns_shifrp ->  password_letters2 ) ) ;
  shifr_memsetv ( ns_shifrp ->  password_letters3 ,
    shifr_memsetv_default_byte ,
    sizeof  ( ns_shifrp ->  password_letters3 ) ) ;
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
