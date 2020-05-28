// Шифр ©2020 Глебов А.Н.
// Shifr ©2020 Glebe A.N.

// Version 4

// RUS
// 2 бита соль
// 2 бита инфа
// итого 4 бита
// таблица шифра: личные 2 бита + соль 2 бита => 4 бита шифрованные
// личные данные b00 => могут быть зашифрованы упорядоченным набором 2^2 = 4шт из 
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
// letter password length : log ( 95 , 20922789888000 ) ≈ 6.735 letters <= 7 letters
//  log ( 62 , 20922789888000 ) ≈ 7.432 letters <= 8 letters

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

// Version 6

// RUS
// 3 бита соль
// 3 бита инфа
// итого 6 бит
// таблица шифра: личные 3 бита + соль 3 бита => 6 бита шифрованные
// личные данные b000 => могут быть зашифрованы упорядоченным набором 2^3 = 8шт из 
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
// log(2,1.26886932186e89) ≈ 296 бит <= 37 байт
// пароль будет 296 бит
// ascii буквы 126-32+1 = 95 шт
// длина буквенного пароля : log ( 95 , 1.26886932186e89 ) ≈ 45.05 букв <= 46 букв
//  log ( 62 , 1.26886932186e89 ) ≈ 49.71 буквы <= 50 букв

# include <stdint.h>
# include <string.h>
# include <stdbool.h>
# include <iso646.h>
// убрать эхо в терминале
// close terminal echo
# include <termios.h>
# include <setjmp.h>
# include "struct.h"

//# define  SHIFR_DEBUG

# define  shifr_number_array_pub( M ) ((M)->HRDG)
# define  shifr_number_array_pri( M ) number::array is private
# define  shifr_number_array  shifr_number_array_pub
# define  number_array  shifr_number_array
  
# define  shifr_number_dec_set0( N ) \
  void shifr_number ## N ## _set0  ( number_type  ( N ) * ) ;
# define  number_dec_set0 shifr_number_dec_set0
  
# define  shifr_number_def_set0( N ) \
  void shifr_number ## N ## _set0  ( number_type  ( N ) * const restrict np ) { \
    memset  ( & ( ( number_array  ( np  ) ) [ 0 ] ) , 0 , N ) ; }
# define  number_def_set0 shifr_number_def_set0

# define  shifr_number_set0( N ) shifr_number ## N ## _set0
# define  number_set0 shifr_number_set0

# define  shifr_number_def_set_byte(  N ) \
void  shifr_number ## N ## _set_byte  ( number_type ( N ) * const restrict np , \
  uint8_t const x ) { \
  memset  ( & ( ( number_array ( np ) ) [ 1 ] ) , 0 , N - 1 ) ; \
  ( number_array ( np ) ) [ 0 ] = x ; }
# define  number_def_set_byte shifr_number_def_set_byte

# define  shifr_number_set_byte( N ) shifr_number ## N ## _set_byte
# define  number_set_byte shifr_number_set_byte

# define  shifr_number_def_elt_copy( N ) \
uint8_t shifr_number ## N ## _elt_copy  ( \
  number_type ( N ) const * const restrict  np  , uint8_t const i ) { \
  return  number_array  ( np  ) [ i ] ; }
# define  number_def_elt_copy shifr_number_def_elt_copy

# define  shifr_number_elt_copy( N ) shifr_number ## N ## _elt_copy
# define  number_elt_copy shifr_number_elt_copy

# define  shifr_number_dec_mul_byte(  N ) \
void  shifr_number ## N ## _mul_byte ( number_type ( N ) * , uint8_t )  ;
# define  number_dec_mul_byte shifr_number_dec_mul_byte

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

# define  shifr_number_mul_byte( N ) shifr_number ## N ## _mul_byte
# define  number_mul_byte shifr_number_mul_byte

# define  shifr_number_def_add(  N ) \
void  shifr_number ## N ## _add  ( number_type ( N ) * const restrict  np  ,  \
  number_type ( N ) const * const restrict  xp ) {  \
  uint8_t per = 0 ; \
  uint8_t i = 0 ; \
  do  { \
    uint16_t  s = ( ( uint16_t  ) ( number_elt_copy ( N ) ( np  , i ) ) ) + \
      ( ( uint16_t  ) number_elt_copy ( N ) ( xp  , i ) ) + \
      ( ( uint16_t  ) per ) ; \
    if ( s >= 0x100  ) {  \
      number_array  ( np  ) [ i ] = s - 0x100 ; \
      per = 1 ; } \
    else  { \
      number_array  ( np  ) [ i ] = s  ;  \
      per = 0 ;  }  \
    ++ i  ; \
  } while ( i < N ) ; }
# define  number_def_add shifr_number_def_add

# define  shifr_number_add( N ) shifr_number ## N ## _add
# define  number_add shifr_number_add

# define  shifr_number_def_not_zero(  N ) \
bool  shifr_number ## N ## _not_zero  ( \
  number_type ( N ) const * const restrict  np  ) { \
  uint8_t const * i = & ( number_array  ( np  ) [ N ] ) ; \
  do {  \
    --  i ; \
    if ( * i )  \
      return  true  ; \
  } while ( i not_eq & ( number_array  ( np  ) [ 0 ] ) ) ;  \
  return  false ; }
# define  number_def_not_zero shifr_number_def_not_zero

# define  shifr_number_not_zero( N ) shifr_number ## N ## _not_zero
# define  number_not_zero shifr_number_not_zero

# define  shifr_number_def_dec(  N ) \
void  shifr_number ## N ## _dec ( \
  number_type ( N ) * const restrict  np  ) { \
  uint8_t  * restrict i = & ( number_array  ( np  ) [ 0 ] ) ; \
  do {  \
    if ( ( * i ) == 0 ) \
      -- ( * i ) ;  \
    else  { \
      -- ( * i ) ;  \
      break ; } \
    ++  i ; \
  } while ( i not_eq & ( number_array  ( np  ) [ N ] ) ) ; }
# define  number_def_dec shifr_number_def_dec

# define  shifr_number_dec( N ) shifr_number ## N ## _dec
# define  number_dec shifr_number_dec

# define  shifr_number_def_div_mod(  N ) \
uint8_t shifr_number ## N ## _div_mod ( \
  number_type ( N ) * const restrict  np , uint8_t const div ) { \
  uint8_t modi  = 0 ; \
  uint8_t i = N ; \
  do {  \
    -- i ;  \
    uint16_t  x = ( ( ( uint16_t  ) modi  ) <<  8 ) bitor  \
      ( ( uint16_t  ) ( number_array  ( np  ) [ i ] ) ) ; \
    modi  = x % div ; \
    number_array  ( np  ) [ i ] = x / div ; \
  } while ( i > 0 ) ; \
  return  modi ; }
# define  number_def_div_mod shifr_number_def_div_mod
# define  shifr_number_div_mod( N ) shifr_number ## N ## _div_mod
# define  number_div_mod shifr_number_div_mod

# define  shifr_number_dec_princ( N ) \
void  shifr_number ## N ## _princ ( number_type ( N ) const * np ,  \
  FILE * fs ) ;
# define  number_dec_princ shifr_number_dec_princ

number_dec_set0 ( 6 )
static  inline  number_def_set_byte ( 6 )
static  inline  number_def_elt_copy ( 6 )
number_dec_mul_byte ( 6 )
static  inline  number_def_add  ( 6 )
static  inline  number_def_not_zero ( 6 )
static  inline  number_def_dec  ( 6 )
static  inline  number_def_div_mod  ( 6 )

# define  shifr_number_princ( N ) shifr_number##N##_princ
# define  number_princ shifr_number_princ

# ifdef SHIFR_DEBUG
shifr_number_dec_princ  ( 6 )
# endif

number_dec_set0 ( 37 )
static  inline  number_def_set_byte ( 37 )
number_dec_mul_byte ( 37 )
static  inline  number_def_elt_copy ( 37 )
static  inline  number_def_add  ( 37 )
static  inline  number_def_not_zero ( 37 )
static  inline  number_def_dec  ( 37 )
static  inline  number_def_div_mod  ( 37 )

# ifdef SHIFR_DEBUG
shifr_number_dec_princ  ( 37 )
# endif

# undef shifr_number_array
# define  shifr_number_array  shifr_number_array_pri

extern  t_ns_shifr  ns_shifr  ;

static inline void  shifr_init ( void  ) {
  { char * j = & ( ns_shifr . letters [ 0 ] ) ;
    uint8_t i = ' ' ;
    do {
      ( * j ) = i ;
      ++ i  ;
      ++ j  ;
    } while ( i <= '~' ) ; }
  // 0x30 '0' - 0x39 '9' , 0x41 'A' - 0x5a 'Z' , 0x61 'a' - 0x7a 'z'  
  { char * j = & ( ns_shifr . letters2 [ 0 ] ) ;
    { uint8_t i = '0' ;
      do {
        ( * j ) = i ;
        ++ i  ;
        ++ j  ;
      } while ( i <= '9' ) ; }
    { uint8_t i = 'A' ;
      do {
        ( * j ) = i ;
        ++ i  ;
        ++ j  ;
      } while ( i <= 'Z'  ) ; }
    { uint8_t i = 'a' ;
      do {
        ( * j ) = i ;
        ++ i  ;
        ++ j  ;
      } while ( i <= 'z'  ) ; } }
  ns_shifr  . filefrom  = stdin ;
  ns_shifr  . fileto = stdout ; }

# define  shifr_string_to_password_templ_dec( N ) \
void  shifr_string_to_password##N##_templ ( strcp string , \
  number_type ( N ) * password ,  \
  strcp letters , uint8_t letterscount  ) ;
# define  string_to_password_templ_dec  shifr_string_to_password_templ_dec
string_to_password_templ_dec  ( 6 )
string_to_password_templ_dec  ( 37 )
# define  shifr_string_to_password_templ( N ) shifr_string_to_password##N##_templ
# define  string_to_password_templ  shifr_string_to_password_templ

# define  shifr_password_to_string_templ_dec( N ) \
void  shifr_password##N##_to_string_templ ( \
  number_type ( N ) const * password0 , strp string ,  \
  strp letters , uint8_t letterscount  ) ;
# define  password_to_string_templ_dec  shifr_password_to_string_templ_dec
password_to_string_templ_dec  ( 6 )
password_to_string_templ_dec  ( 37 )  
# define  shifr_password_to_string_templ( N ) shifr_password##N##_to_string_templ
# define  password_to_string_templ  shifr_password_to_string_templ
  
// inits array [ 0..15 , 0..14 , ... , 0..2 , 0..1 ]
void  shifr_generate_pass4 ( void ) ;

// inits array [ 0..63 , 0..62 , ... , 0..2 , 0..1 ]
void  shifr_generate_pass6 ( void ) ;

// [ 0..15 , 0..14 , 0..13 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ] =
// = x + y * 16 + z * 16 * 15 + ... + u * 16! / 2 / 3 + v * 16! / 2 = 0 .. 16!-1
void  shifr_pass_to_array4 ( void ) ;

// [ 0..63 , 0..62 , 0..61 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ] =
// = x + y * 64 + z * 64 * 63 + ... + u * 64! / 2 / 3 + v * 64! / 2 = 0 .. 64!-1
void  shifr_pass_to_array6 ( void ) ;

// Отключить эхо-вывод и буферизацию ввода
void set_keypress (void)  ;

// Восстановление дефолтного состояния
void reset_keypress ( void  ) ;

static  inline  void  enter_password6 ( void ) {
  char p60 [ 100 ] ;
  set_keypress  ( ) ;
  char ( * const p6 ) [ 100 ] = (char(*const)[100])
    fgets ( & ( p60 [ 0 ] ) , 100 , stdin ) ;
  reset_keypress ( ) ;
  char * j = & ( ( * p6 ) [ 0 ]  ) ;
  while ( ( ( * j ) not_eq '\n' ) and
    ( ( * j ) not_eq '\00' ) and
    ( j < ( & ( * p6 ) [ 100 ] ) ) )
    ++ j ;  
  if ( j < ( & ( ( * p6 ) [ 100 ] ) ) )
    ( * j ) = '\00' ;
  else  {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      ( strcp ) & u8"в пароле нет конца строки" :
      ( strcp ) & "there is no end of line in the password" ) ;
    longjmp ( ns_shifr  . jump  , 1 ) ; }
  char  password_letters6 [ 100 ] ;
  if ( ns_shifr . password_alphabet == 95 ) {
    string_to_password_templ  ( 37 ) ( p6 ,
      & ns_shifr . raspr6  . pass ,
      & ns_shifr . letters ,  letters_count ) ;
    password_to_string_templ  ( 37 ) ( & ns_shifr . raspr6  . pass ,
      & password_letters6 , & ns_shifr . letters , letters_count ) ; }
  else {
    string_to_password_templ  ( 37 ) ( p6 ,
      & ns_shifr . raspr6  . pass ,
      & ns_shifr . letters2 ,  letters_count2 ) ;
    password_to_string_templ  ( 37 ) ( & ns_shifr . raspr6  . pass ,
      & password_letters6 , & ns_shifr . letters2 , letters_count2 ) ; }
  if  ( strcmp ( &  ( password_letters6 [ 0 ] ) , & ( ( * p6  ) [ 0 ] ) ) )
    fprintf  ( stderr , ( ns_shifr . localerus ?
      u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'.\n" :
      "Warning! Password \'%s\' is very large. Same as \'%s\'.\n" )
      , & ( ( * p6  ) [ 0 ] ) , & ( password_letters6  [ 0 ] ) ) ; }
      
static  inline  void  enter_password4 ( void ) {
  char p40 [ 20 ] ;
  set_keypress  ( ) ;
  char ( * const p4 ) [ 20 ] = (  char  ( * const ) [ 20  ] )
    fgets ( & ( p40 [ 0 ] ) , 20 , stdin ) ;
  reset_keypress ( ) ;
  char * j = & ( ( * p4 ) [ 0 ]  ) ;
  while ( ( ( * j ) not_eq '\n' ) and
    ( ( * j ) not_eq '\00' ) and
    ( j < ( & ( * p4 ) [ 20 ] ) ) )
    ++ j ;  
  if ( j < ( & ( ( * p4 ) [ 20 ] ) ) )
    ( * j ) = '\00' ;
  else  {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      ( strcp ) & u8"в пароле нет конца строки" :
      ( strcp ) & "there is no end of line in the password" ) ;
    longjmp ( ns_shifr  . jump  , 1 ) ; }
  if ( ns_shifr . password_alphabet == 95 )
    string_to_password_templ  ( 6 ) ( p4 , & ns_shifr . raspr4  . pass ,
      & ns_shifr . letters ,  letters_count ) ;
  else
    string_to_password_templ  ( 6 ) ( p4 , & ns_shifr . raspr4  . pass ,
      & ns_shifr . letters2 ,  letters_count2 ) ;
  char  password_letters [ 20 ] ;
  if ( ns_shifr . password_alphabet == 95 )
    password_to_string_templ  ( 6 ) ( & ns_shifr . raspr4  . pass ,
      & password_letters , & ns_shifr . letters , letters_count ) ;
  else
    password_to_string_templ  ( 6 ) ( & ns_shifr . raspr4  . pass ,
      & password_letters , & ns_shifr . letters2 , letters_count2 ) ;
  if  ( strcmp ( &  ( password_letters  [ 0 ] ) , & ( ( * p4  ) [ 0 ] ) ) )
    fprintf  ( stderr , ( ns_shifr . localerus ?
      u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
      "Warning! Password \'%s\' is very large. Same as \'%s\'\n" )
      , & ( ( * p4  ) [ 0 ] ) , & ( password_letters [ 0 ] ) ) ; }
      
# define  enter_password  shifr_enter_password
static  inline  void  enter_password (  void  ) {
  switch ( ns_shifr . use_version ) {
    case  6 :
      enter_password6  ( ) ;
      break ;
    case 4 :
      enter_password4  ( ) ;
      break ;
    default :
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"enter_password:Неизвестная версия %d\n" :
        "enter_password:Unknown version %d\n" ) , ns_shifr . use_version  ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( strcp ) & u8"enter_password:Неизвестная версия" :
        ( strcp ) & "enter_password:Unknown version" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; } }

# define  streambuf_file_pub( M ) ((M)->oRmq)
# define  streambuf_file_pri( M ) "streambuf::file is private"
# define  streambuf_file  streambuf_file_pub

# define  streambuf_buf_pub( M ) ((M)->FmoX)
# define  streambuf_buf_pri( M ) "streambuf::buf is private"
# define  streambuf_buf  streambuf_buf_pub

# define  streambuf_bufbitsize_pub( M ) ((M)->XUvM)
# define  streambuf_bufbitsize_pri( M ) "streambuf::bufbitsize is private"
# define  streambuf_bufbitsize  streambuf_bufbitsize_pub

# define  streambuf_bytecount_pub( M ) ((M)->D6h7)
# define  streambuf_bytecount_pri( M ) "streambuf::bytecount is private"
# define  streambuf_bytecount  streambuf_bytecount_pub

static  inline  void  streambuf_init  ( t_streambuf * const restrict me  ,
  FILE  * const f ) {
  streambuf_file  ( me  ) = f ;
  streambuf_buf ( me  ) = 0 ;
  streambuf_bufbitsize  ( me  ) = 0 ;
  streambuf_bytecount ( me  ) = 0 ; }
  
# undef streambuf_file
# define  streambuf_file  streambuf_file_pri
# undef streambuf_buf
# define  streambuf_buf  streambuf_buf_pri
# undef streambuf_bufbitsize
# define  streambuf_bufbitsize  streambuf_bufbitsize_pri
# undef streambuf_bytecount
# define  streambuf_bytecount  streambuf_bytecount_pri
  
extern  t_streambuf shifr_filebuffrom ;
extern  t_streambuf shifr_filebufto ;

# define  initarr shifr_initarr
static inline  void  initarr ( arrp  const p , uint8_t const codefree ,
  size_t const loc_shifr_deshi_size ) {
  uint8_t * i = & ( ( * p ) [ loc_shifr_deshi_size  ] ) ;
  do {
    --  i ;
    ( * i ) = codefree ;
  } while ( i not_eq  & ( ( * p ) [ 0 ] ) ) ; }

// пароль раскладываем в таблицу шифровки , дешифровки
  // пароль % 0x10 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  // пароль делим на 16, остаются 15! вариантов пароля
// пароль % 0xf = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
//  секретных кодов для соли+данных 0x1  
// в deshi нужна соль

// we lay out the password in the table of encryption, decryption
// password % 0x10 = 0xa means that 0xa is the encrypted code for salt + data 0x0
// divide the password by 16, 15! remain password options
// password % 0xf = 0xa is the sequence number for the remaining NOT occupied from
//  0xff secret codes for salt + data 0x1
// deshi needs salt

# define  shifr_password_load_def(  N , SDS ) \
void  shifr_password##N##_load  ( number_type ( N ) const * const password0 , \
  arrp const shifrp , arrp const deship ) { \
  initarr ( shifrp , 0xff , SDS )  ;  \
  initarr ( deship , 0xff , SDS )  ;  \
  uint8_t arrind  [ SDS  ] ;  \
  { uint8_t * arrj  = & ( arrind  [ SDS  ] ) ;  \
    uint8_t j = SDS  ;  \
    do  { \
      --  arrj  ; \
      --  j ; \
      ( * arrj )  = j ; \
    } while ( arrj  not_eq & ( arrind  [ 0 ] ) ) ;  } \
  uint8_t inde  = 0 ; \
  number_type ( N ) password = * password0 ; \
  do {  \
    { uint8_t cindex = number_div_mod ( N ) ( & password , SDS - inde ) ;  \
      uint8_t * arrind_cindexp = & (  arrind [ cindex ] ) ; \
      ( * shifrp ) [ inde ] = ( * arrind_cindexp ) ;  \
      ( * deship ) [ * arrind_cindexp ] = inde ;  \
      memmove ( arrind_cindexp , arrind_cindexp + 1 , \
        SDS  - inde  - cindex - 1 ) ; } \
    ++ inde  ;  \
  } while ( inde < SDS ) ; }
static  inline  shifr_password_load_def (  6 , shifr_deshi_size2 )
static  inline  shifr_password_load_def (  37 , shifr_deshi_size6 )
# define  shifr_password_load( N ) shifr_password##N##_load
# define  password_load shifr_password_load

void  shifr_password_load_uni ( void  ) ;

# ifdef SHIFR_DEBUG
# define  printarr  shifr_printarr
void  printarr  ( strcp name , arrcp p ,
  size_t arrsize , FILE * f ) ;
# endif
  
void  string_to_password ( void ) ;
# define  password_to_string  shifr_password_to_string
void  password_to_string  ( void  ) ;
void  shifr_encode  ( void  ) ;
void  shifr_decode  ( void  ) ;

# define  generate_password shifr_generate_password
static  inline  void  generate_password ( void  ) {
  switch  ( ns_shifr . use_version  ) {
    case  4 : 
      shifr_generate_pass4  ( ) ;
      shifr_pass_to_array4  ( ) ;
# ifdef SHIFR_DEBUG
      fputs ( ( ns_shifr . localerus ?
        u8"generate_password:внутренний пароль = " :
        "generate_password:internal password = " ) , stderr ) ;
      number_princ  ( 6 ) ( & ns_shifr . raspr4  . pass , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif
      break ;
    case 6 :
      shifr_generate_pass6  ( ) ;
      shifr_pass_to_array6  ( ) ;
# ifdef SHIFR_DEBUG
      fputs ( ( ns_shifr . localerus ?
        u8"generate_password:внутренний пароль = " :
        "generate_password:internal password = " ) , stderr ) ;
      number_princ  ( 37 ) ( & ns_shifr . raspr6  . pass , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif
      break ;
    default :
      fprintf ( stderr , ( ns_shifr . localerus ?
        u8"generate_password:неопознанная версия : \'%d\'\n" :
        "generate_password:unrecognized version : \'%d\'\n" ) ,
        ns_shifr . use_version ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( strcp ) & u8"generate_password:неопознанная версия" :
        ( strcp ) & "generate_password:unrecognized version" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; } }

