// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

// Version 2

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
// letter password length : log ( 95 , 20922789888000 ) ≈ 6.735 letters <= 7 letters
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
// log(2,1.26886932186e89) ≈ 296 bits <= 37 bytes
// пароль будет 296 бит
// ascii буквы 126-32+1 = 95 шт
// длина буквенного пароля : log ( 95 , 1.26886932186e89 ) ≈ 45.05 букв <= 46 букв
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
// letter password length : log ( 95 , 1.26886932186e89 ) ≈ 45.05 letters <= 46 letters
//  log ( 62 , 1.26886932186e89 ) ≈ 49.71 letters <= 50 letters
//  log ( 26 , 1.26886932186e89 ) ≈ 62.97 letters <= 63 letters
//  log ( 10 , 1.26886932186e89 ) ≈ 89.1 digits <= 90 digits

# include <stdio.h>
# include <errno.h>
# include <string.h> // memset
# include <iso646.h> // bitand
# include "define.h"

# ifdef SHIFR_SYSCALL_RANDOM
# include <sys/syscall.h>
# else
# include <sys/random.h>
# endif

# include "public.h"
# include "struct.h"

# include <stddef.h> // offsetof

# define  shifr_number_pub_to_priv( N ) shifr_number_pub_to_priv_ ## N
# define  number_pub_to_priv  shifr_number_pub_to_priv

# define  shifr_number_pub_to_priv_def( N ) \
number_priv_type ( N ) * shifr_number_pub_to_priv ( N ) ( \
  shifr_number_type  ( N ) * const n ) { \
  return  ( number_priv_type  ( N ) * ) ( \
    ( ( uint8_t * ) n ) - offsetof ( number_priv_type ( N ) , pub ) ) ; }
    
static  inline  shifr_number_pub_to_priv_def  ( v2 )
static  inline  shifr_number_pub_to_priv_def  ( number_size3 )

# define  shifr_number_const_pub_to_priv( N ) shifr_number_const_pub_to_priv_ ## N
# define  number_const_pub_to_priv  shifr_number_const_pub_to_priv

# define  shifr_number_const_pub_to_priv_def( N ) \
number_priv_type ( N ) const * shifr_number_const_pub_to_priv ( N ) (  \
  shifr_number_type  ( N ) const * const n ) { \
  return  ( number_priv_type  ( N ) const * ) ( \
    ( ( uint8_t * ) n ) - offsetof ( number_priv_type ( N ) , pub ) ) ; }
    
static  inline  shifr_number_const_pub_to_priv_def  ( v2 )
static  inline  shifr_number_const_pub_to_priv_def  ( number_size3 )

# define  shifr_number_def_set0( N , D ) \
  void shifr_number ## N ## _set0  ( shifr_number_type  ( N ) * const np ) { \
    memset  ( & ( number_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) , 0 , D ) ; }
# define  number_def_set0 shifr_number_def_set0

# define  shifr_number_def_elt_copy( N ) \
uint8_t shifr_number ## N ## _elt_copy  ( \
  shifr_number_type ( N ) const * const np  , uint8_t const i ) { \
  return  number_const_pub_to_priv ( N ) ( np ) -> arr [ i ] ; }
# define  number_def_elt_copy shifr_number_def_elt_copy

# define  shifr_number_elt_copy( N ) shifr_number ## N ## _elt_copy
# define  number_elt_copy shifr_number_elt_copy

static  inline  number_def_elt_copy ( v2 )
static  inline  number_def_elt_copy ( number_size3 )

# define  shifr_number_def_mul_byte(  N , D ) \
void  shifr_number ## N ## _mul_byte ( shifr_number_type ( N ) * const np  , \
  uint8_t const byte ) {  \
  if ( byte == 0 ) {  \
    number_set0 ( N ) ( np ) ; \
    return  ; } \
  if ( byte == 1 )  \
    return ; \
  uint8_t per = 0 ; \
  { uint8_t i = 0 ; \
    do { \
      uint16_t const x = ( uint16_t ) ( ( ( uint16_t  ) ( \
        number_elt_copy ( N ) ( np , i ) ) ) * \
        ( ( uint16_t  ) byte  ) + ( ( uint16_t  ) per ) ) ; \
      number_pub_to_priv ( N ) ( np ) -> arr [ i ] = ( uint8_t ) ( x bitand 0xff ) ; \
      per = ( uint8_t ) ( x >>  8 ) ; \
      ++  i ; \
    } while ( i < D ) ; } }
# define  number_def_mul_byte shifr_number_def_mul_byte

number_def_set0 ( v2 , shifr_number_size2 )
number_def_mul_byte ( v2 , shifr_number_size2 )
number_def_set0 ( number_size3 , number_size3 )
number_def_mul_byte ( number_size3 , number_size3 )

# define  shifr_number_def_add(  N , D ) \
void  shifr_number ## N ## _add  ( shifr_number_type ( N ) * const restrict  np  , \
  shifr_number_type ( N ) const * const restrict  xp ) {  \
  uint8_t per = 0 ; \
  uint8_t i = 0 ; \
  do  { \
    uint16_t const s = ( uint16_t  ) ( ( ( uint16_t  ) (  \
      number_elt_copy ( N ) ( np , i ) ) ) + \
      ( ( uint16_t  ) number_elt_copy ( N ) ( xp , i ) ) + \
      ( ( uint16_t  ) per ) ) ; \
    if ( s >= 0x100  ) {  \
      number_pub_to_priv ( N ) ( np ) -> arr [ i ] = ( uint8_t ) ( s - 0x100 ) ; \
      per = 1 ; } \
    else  { \
      number_pub_to_priv ( N ) ( np ) -> arr [ i ] = ( uint8_t ) s  ;  \
      per = 0 ;  }  \
    ++ i  ; \
  } while ( i < D ) ; }
# define  number_def_add shifr_number_def_add

# define  shifr_number_add( N ) shifr_number ## N ## _add
# define  number_add shifr_number_add

static  inline  number_def_add  ( v2 , shifr_number_size2 )
static  inline  number_def_add  ( number_size3 , number_size3 )

# define  shifr_number_def_not_zero(  N , D ) \
bool  shifr_number ## N ## _not_zero  ( \
  shifr_number_type ( N ) const * const np  ) { \
  uint8_t const * i = & ( number_const_pub_to_priv ( N ) ( np ) -> arr [ D ] ) ; \
  do {  \
    --  i ; \
    if ( * i )  \
      return  true  ; \
  } while ( i not_eq & ( number_const_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) ) ;  \
  return  false ; }
# define  number_def_not_zero shifr_number_def_not_zero

# define  shifr_number_not_zero( N ) shifr_number ## N ## _not_zero
# define  number_not_zero shifr_number_not_zero

static  inline  number_def_not_zero ( v2 , shifr_number_size2 )
static  inline  number_def_not_zero ( number_size3 , number_size3 )

# define  shifr_number_def_dec(  N , D ) \
void  shifr_number ## N ## _dec ( shifr_number_type ( N ) * const np  ) { \
  uint8_t  * i = & ( number_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) ; \
  do {  \
    if ( ( * i ) == 0 ) \
      ( * i ) = 0xffU ; \
    else  { \
      -- ( * i ) ;  \
      break ; } \
    ++  i ; \
  } while ( i not_eq & ( number_pub_to_priv ( N ) ( np ) -> arr [ D ] ) ) ; }
# define  number_def_dec shifr_number_def_dec

# define  shifr_number_dec( N ) shifr_number ## N ## _dec
# define  number_dec shifr_number_dec

static  inline  number_def_dec  ( v2 , shifr_number_size2 )
static  inline  number_def_dec  ( number_size3 , number_size3 )

# define  shifr_number_def_div_mod(  N , D ) \
uint8_t shifr_number ## N ## _div_mod ( \
  shifr_number_type ( N ) * const np0 , uint8_t const div ) { \
  number_priv_type ( N ) * const np = number_pub_to_priv ( N ) ( np0 ) ; \
  uint8_t modi  = 0 ; \
  uint8_t i = D ; \
  do {  \
    -- i ;  \
    uint16_t const x = ( uint16_t  ) ( ( ( ( uint16_t  ) modi  ) <<  8 ) bitor  \
      ( ( uint16_t  ) ( np -> arr [ i ] ) ) ) ; \
    modi  = ( uint8_t ) ( x % div ) ; \
    np -> arr [ i ] = ( uint8_t ) ( x / div ) ; \
  } while ( i > 0 ) ; \
  return  modi ; }
# define  number_def_div_mod shifr_number_def_div_mod
# define  shifr_number_div_mod( N ) shifr_number ## N ## _div_mod
# define  number_div_mod shifr_number_div_mod

static  inline  number_def_div_mod  ( v2 , shifr_number_size2 )
static  inline  number_def_div_mod  ( number_size3 , number_size3 )

# define  shifr_number_def_set_byte(  N , D ) \
void  shifr_number ## N ## _set_byte  ( shifr_number_type ( N ) * const np0 , \
  uint8_t const x ) { \
  number_priv_type ( N ) * const np = number_pub_to_priv ( N ) ( np0 ) ; \
  memset  ( & ( np -> arr [ 1 ] ) , 0 , D - 1 ) ; \
  np -> arr [ 0 ] = x ; }
# define  number_def_set_byte shifr_number_def_set_byte

# define  shifr_number_set_byte( N ) shifr_number ## N ## _set_byte
# define  number_set_byte shifr_number_set_byte

static  inline  number_def_set_byte ( v2 , shifr_number_size2 )
static  inline  number_def_set_byte ( number_size3 , number_size3 )
  
# ifdef SHIFR_DEBUG
void  printarr  ( shifr_strcp const  name , shifr_arrcp const p ,
  size_t const arrsize , FILE * const f ) {
  fprintf  ( f  , u8"%s = [ " , * name  ) ;
  uint8_t const * i = & ( ( * p ) [ 0 ] ) ;
  do {
    fprintf  ( f  , "%x , " , ( int ) ( * i ) ) ; 
    ++  i ;
  } while ( i not_eq  & ( ( * p ) [ arrsize ] ) ) ;
  fputs ( u8"]\n" , f ) ; }
# endif
    
# define  shifr_password_to_string_templ_def( N ) \
void  shifr_password  ##  N ##  _to_string_templ ( \
  shifr_number_type ( N ) const * const password0 , shifr_strvp const string , \
  shifr_strp letters , uint8_t const letterscount  ) { \
  char  volatile  * stringi = & ( ( * string )  [ 0 ] ) ; \
  if ( number_not_zero  ( N ) ( password0 ) ) { \
    number_priv_type ( N ) password = * number_const_pub_to_priv ( N ) ( password0 ) ; \
    do {  \
      /* здесь предыдущие размеры заняли место паролей */ \
      number_dec ( N ) ( & password . pub ) ;  \
      ( * stringi ) = ( * letters ) [ \
        number_div_mod ( N ) ( & password . pub , letterscount ) ] ;  \
      ++  stringi ; \
    } while ( number_not_zero ( N ) ( & password . pub ) ) ; }  \
  ( * stringi ) = '\00' ;  }
# define  password_to_string_templ_def  shifr_password_to_string_templ_def
password_to_string_templ_def  ( v2 )
password_to_string_templ_def  ( number_size3 )

# define  shifr_string_to_password_templ_def( N ) \
void  shifr_string_to_password  ##  N ##  _templ ( t_ns_shifr * const ns_shifrp , \
  shifr_strvcp  const string  , shifr_number_type ( N ) * const password ,  \
  shifr_strcp const letters , uint8_t const letterscount  ) { \
  char  volatile  const * restrict stringi = & ( ( * string )  [ 0 ] ) ; \
  if  ( ( * stringi ) == '\00' ) { \
    number_set0 ( N ) ( password ) ; \
    return ; } \
  number_priv_type ( N ) pass ; \
  number_set0 ( N ) ( & pass . pub ) ; \
  number_priv_type ( N ) mult ;  \
  number_set_byte ( N ) ( & mult . pub , 1 ) ;  \
  do  { \
    uint8_t i = letterscount ;  \
    do {  \
      -- i ;  \
      if ( ( * stringi ) == ( * letters ) [ i ] ) \
        goto found ; \
    } while ( i ) ; \
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?  \
      ( shifr_strcp ) & u8"неправильная буква в пароле" : \
      ( shifr_strcp ) & "wrong letter in password" ) ;  \
    longjmp ( ns_shifrp  -> jump  , 1 ) ; \
found : ; \
    { number_priv_type ( N ) tmp = mult ;  \
      number_mul_byte ( N ) ( & tmp . pub , ( uint8_t ) ( i + 1 ) ) ; \
      number_add ( N ) ( &  pass . pub , & tmp . pub )  ; }  \
    number_mul_byte ( N ) ( & mult . pub , letterscount ) ; \
    ++  stringi ; \
  } while ( ( * stringi ) not_eq '\00' ) ;  \
  ( * number_pub_to_priv ( N ) ( password  ) ) = pass ; }
# define  string_to_password_templ_def  shifr_string_to_password_templ_def
string_to_password_templ_def  ( v2 )
string_to_password_templ_def  ( number_size3 )
  
# include <unistd.h> // ssize_t

// generate random number [ fr .. to ]
static  unsigned  int uirandfrto  ( t_ns_shifr * const ns_shifrp ,
  unsigned  int const fr , unsigned  int const to ) {
# ifdef SHIFR_DEBUG
  if ( fr >= to ) {
    fprintf ( stderr  , "uirandfrto : fr >= to , fr = %u , to = %u\n"  ,
      fr , to ) ;
    ns_shifrp  -> string_exception  = ( shifr_strcp ) "uirandfrto : fr >= to" ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  if ( fr + 0x100 <= to ) {
    fprintf ( stderr  , "uirandfrto : fr + 0x100 <= to , fr = %u , to = %u\n"  ,
      fr , to ) ;
    ns_shifrp  -> string_exception  = ( shifr_strcp ) "uirandfrto : fr + 0x100 <= to" ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
# endif
  uint8_t buf ;
  do {
# ifdef SHIFR_DEBUG
    ssize_t const r = 
# endif
# ifdef SHIFR_SYSCALL_RANDOM
      syscall ( SYS_getrandom , & buf , 1 , 0 ) ;
# else
      getrandom ( & buf , 1 , 0 ) ;
# endif
# ifdef SHIFR_DEBUG
    if ( r == -1 ) {
      perror  ( "uirandfrto : getrandom" ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp ) "uirandfrto : getrandom" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
    if ( r not_eq 1 ) {
      fprintf ( stderr  , "uirandfrto : r = %ld not_eq 1\n"  , r ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp ) "uirandfrto : r not_eq 1" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
# endif // SHIFR_DEBUG
  } while ( buf + 0x100 % ( to - fr + 1 ) >= 0x100 ) ;
  return  fr + buf % ( to - fr + 1 ) ; }

// data_size = 4
static  void datasole2 ( t_ns_shifr * const ns_shifrp , shifr_arrcp const secretdata ,
  shifr_arrp const secretdatasole , size_t const data_size ) {
  uint8_t const * restrict  id = &  ( ( * secretdata  ) [ data_size ] ) ;
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ data_size ] ) ;
  uint8_t ran ;
# ifdef SHIFR_DEBUG
  ssize_t const r =
# endif
# ifdef SHIFR_SYSCALL_RANDOM
    syscall ( SYS_getrandom , & ran , 1 , 0 ) ;
# else
    getrandom ( & ran , 1 , 0 ) ;
# endif
# ifdef SHIFR_DEBUG
    if ( r == -1 ) {
      perror  ( "datasole2 : getrandom" ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp ) "datasole2 : getrandom" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
    if ( r not_eq 1 ) {
      fprintf ( stderr  , "datasole2 : r = %ld not_eq 1\n"  , r ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp ) "datasole2 : r not_eq 1" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
# endif // SHIFR_DEBUG
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 10 =>
    //   10_00 или 10_01 или 10_10 или 10_11
    // в таблице всё рядом, 4 варианта равномерно распределены
    ( * ids ) = ( uint8_t ) (
      ( ( * id  ) <<  2 ) bitor
      ( ran bitand  0x3 ) ) ;
    ran >>= 2 ;
  } while ( id not_eq & ( ( * secretdata  ) [ 0 ] ) ) ; }

// data_size = 1 .. 3
static void datasole3 ( t_ns_shifr * const ns_shifrp , shifr_arrcp const secretdata ,
  shifr_arrp const secretdatasole , size_t const data_size ) {
  uint8_t const * restrict  id = &  ( ( * secretdata  ) [ data_size ] ) ;
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ data_size ] ) ;
  int const arans = ( ( data_size == 3 ) ? 2 : 1 ) ;
  uint8_t aran [ arans ] ;
# ifdef SHIFR_DEBUG
  ssize_t const r = 
# ifdef SHIFR_SYSCALL_RANDOM
    syscall ( SYS_getrandom , & ( aran [ 0 ] ) , arans , 0 ) ;
# else
    getrandom ( & ( aran [ 0 ] ) , ( size_t ) arans , 0 ) ;
# endif
    if ( r == -1 ) {
      perror  ( "datasole3 : getrandom" ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp ) "datasole3 : getrandom" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
    if ( r not_eq arans ) {
      fprintf ( stderr  , "datasole3 : r = %ld not_eq %d\n"  , r , arans ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp ) "datasole3 : r not_eq arans" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
# endif // SHIFR_DEBUG
  unsigned  int ran = ( ( unsigned  int ) ( aran [ 0 ] ) ) ;
  if ( arans == 2 )
    ran |=  ( ( ( unsigned  int ) ( aran [ 1 ] ) ) << 8 ) ;
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 101 =>
    //   101_000 или 101_001 или ... или 101_111
    // в таблице всё рядом, 8 вариантов равномерно распределены
    ( * ids ) = ( uint8_t )
      ( ( ( unsigned int ) ( ( * id  ) <<  3 ) ) bitor
      ( ran bitand  0x7 ) ) ;
    ran >>= 3 ;
  } while ( id not_eq & ( ( * secretdata  ) [ 0 ] ) ) ; }

// Отключить эхо-вывод и буферизацию ввода
void set_keypress ( t_ns_shifr * const ns_shifrp ) {
  if  ( tcgetattr ( 0 , & ns_shifrp  -> stored_termios  ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      u8"ошибка чтения tcgetattr : %s\n" :
      "error read tcgetattr : %s\n" ) , se ) ;
    ns_shifrp  -> string_exception  = ( shifr_strcp ) se ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  struct termios new_termios = ns_shifrp -> stored_termios  ;
  new_termios.c_lflag  and_eq ( unsigned int ) ( ~ ( ECHO bitor ICANON ) ) ;
  new_termios.c_cc  [ VMIN  ] = 1 ;  
  new_termios.c_cc  [ VTIME ] = 0 ; 
  if  ( tcsetattr ( 0 , TCSANOW , & new_termios ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      u8"ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifrp  -> string_exception  = ( shifr_strcp ) se ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; } }
 
// Восстановление дефолтного состояния
void reset_keypress ( t_ns_shifr * const ns_shifrp ) {
  if  ( tcsetattr ( 0 , TCSANOW , & ns_shifrp -> stored_termios ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      u8"ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifrp  -> string_exception  = ( shifr_strcp ) se ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; } }

static  inline  uint8_t letter_to_bits6 ( char  const letter  ) {
  return  ( uint8_t ) ( letter  - ';' ) ; }

// читаю 6 бит
// 6 bits reads
bool  isEOBstreambuf_read6bits ( t_ns_shifr * const ns_shifrp ,
  uint8_t * const encrypteddata , size_t * const  readsp ,
  uint8_t const * restrict * const input_bufferp , size_t const inputs ) {
  t_streambuf * const restrict me = & ns_shifrp -> filebuffrom ;
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
    } while ( ( buf < ( ( uint8_t ) ';' ) ) or
      ( buf > ( ( uint8_t ) 'z' ) ) ) ;
    ( * encrypteddata ) = letter_to_bits6 ( ( char ) buf ) ;
    return  false ; }
  if  ( ( me -> bufbitsize ) >= 6 ) {
    me -> bufbitsize = ( uint8_t ) ( ( me -> bufbitsize ) - 6U ) ;
    ( * encrypteddata ) = ( me -> buf ) bitand ( 0x40 - 1 ) ;
    ( me -> buf ) >>= 6 ;
    return  false ; }
  uint8_t buf = * * input_bufferp  ;
  ++  ( * readsp ) ;
  ++  ( * input_bufferp  ) ;
  ( * encrypteddata ) = ( ( me -> buf ) bitor 
    ( buf <<  ( me -> bufbitsize ) ) ) bitand ( 0x40 - 1 )  ;
  me -> buf = ( uint8_t ) ( buf >> ( 6 - ( me -> bufbitsize ) ) ) ;
  // + 8 - 6
  me -> bufbitsize = ( uint8_t ) ( ( me -> bufbitsize ) + 2 ) ;
  return  false ; }

// ';' = 59 ... 'z' = 122 , 122 - 59 + 1 == 64
static  inline  char  bits6_to_letter ( uint8_t const bits6 ) {
  return  ( char ) ( ';'  + bits6 ) ; }

// пишу по шесть бит
// secretdatasolesize - количество шести-битных отделов (2 или 3)
// encrypteddata - массив шести-битных чисел
// I write in six bits
// secretdatasolesize - the number of six-bit divisions (2 or 3)
// encrypteddata - array of six-bit numbers
static void  streambuf_write3 ( t_ns_shifr * const ns_shifrp ,
  t_streambuf * const me  , uint8_t const (  * const encrypteddata ) [ 3 ] ,
  uint8_t const secretdatasolesize , bool const  flagtext ,
  uint8_t * restrict * const output_bufferp , size_t * const writesp ,
  size_t  const outputs ) {
  if  ( flagtext  ) {
    uint8_t i = 0 ;
    do {
      char  buf2  = bits6_to_letter ( ( * encrypteddata ) [ i ] ) ;
        if ( ( * writesp ) >= outputs ) {
          ns_shifrp  -> string_exception  = ( ns_shifrp  -> localerus ? 
            ( shifr_strcp ) & u8"streambuf_write3: переполнение буфера (flagtext)"  :
            ( shifr_strcp ) & "streambuf_write3: buffer overflow (flagtext)" ) ;
          longjmp ( ns_shifrp  -> jump  , 1 ) ; }
        ( * * output_bufferp ) = ( uint8_t ) buf2 ;
        ++  ( * output_bufferp )  ;
        ++  ( * writesp ) ;
        ++  ( me -> bytecount ) ;
        if  ( ( me -> bytecount ) >=  60  ) {
          if ( ( * writesp ) >= outputs ) {
            ns_shifrp  -> string_exception  = ( ns_shifrp  -> localerus ? 
              ( shifr_strcp ) & u8"streambuf_write3: переполнение буфера для '\\n'"  :
              ( shifr_strcp ) & "streambuf_write3: buffer overflow for '\\n'" ) ;
            longjmp ( ns_shifrp  -> jump  , 1 ) ; }
          ( * * output_bufferp ) = '\n' ;
          ++  ( * output_bufferp )  ;
          ++  ( * writesp ) ;
          me -> bytecount = 0 ; }
      ++  i ;
    } while ( i < secretdatasolesize ) ; }
  else  {
    uint8_t i = 0 ;
    do {
      if  ( ( me -> bufbitsize ) < 2 ) {
        me -> buf = ( me -> buf ) bitor
          ( uint8_t ) ( ( ( * encrypteddata ) [ i ] ) << ( me -> bufbitsize ) ) ;
        me -> bufbitsize = ( uint8_t ) ( ( me -> bufbitsize ) + 6 ) ; }
      else  {
        uint8_t const to_write  = ( uint8_t ) ( ( ( ( * encrypteddata ) [ i ] ) <<
          ( me -> bufbitsize  ) ) bitor ( me -> buf ) ) ;
        if ( ( * writesp ) >= outputs ) {
          ns_shifrp  -> string_exception  = ( ns_shifrp  -> localerus ? 
            ( shifr_strcp ) & u8"streambuf_write3: переполнение буфера (flagdigit)"  :
            ( shifr_strcp ) & "streambuf_write3: buffer overflow (flagdigit)" ) ;
          longjmp ( ns_shifrp  -> jump  , 1 ) ; }
        ( * * output_bufferp ) = to_write ;
        ++  ( * output_bufferp )  ;
        ++  ( * writesp ) ;
        // + 6 - 8
        me -> bufbitsize = ( uint8_t ) ( ( me -> bufbitsize ) - 2U ) ;
        me -> buf = ( uint8_t ) ( ( ( * encrypteddata ) [ i ] ) >>
          ( 6 - ( me -> bufbitsize ) ) ) ;  } 
        ++  i ;
      } while ( i < secretdatasolesize ) ; } }
  
static inline void  data_xor3  ( uint8_t * const restrict  old_last_data ,
  uint8_t * const restrict  old_last_sole ,
  shifr_arrp  const secretdatasole  , size_t  const data_size ) {
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ 0 ] ) ;
  do {
    uint8_t const cur_data = ( * ids ) >> 3 ;
    uint8_t const cur_sole = ( * ids ) bitand 0x7 ;
    // главное данные , хвост - соль : 101 =>
    //   101_000 или 101_001 или ... или 101_111
    // в таблице всё рядом, 8 вариантов равномерно распределены
    // данные сыпью предыдущей солью
    ( * ids ) = ( uint8_t ) ( ( * ids ) xor  ( ( * old_last_sole ) << 3  ) ) ;
    ( * ids ) xor_eq  ( * old_last_data ) ;
    // берю свежую соль
    ( * old_last_sole ) = cur_sole ;
    ( * old_last_data ) = cur_data ;
    ++  ids ;
  } while ( ids not_eq & ( ( * secretdatasole ) [ data_size ] ) ) ; }

# define  crypt_decrypt shifr_crypt_decrypt
static inline void  crypt_decrypt ( shifr_arrp const datap , shifr_arrcp const tablep ,
  shifr_arrp const encrp , size_t const data_size ) {
  uint8_t const * id = & ( ( * datap ) [ data_size ] ) ;
  uint8_t * ied = & ( ( * encrp ) [ data_size ] ) ;
  do {
    -- id ;
    --  ied ;
    ( * ied ) = ( * tablep ) [ * id ] ;
  } while ( id not_eq & ( ( * datap ) [ 0 ] ) ) ; }

uint8_t streambuf_writeflushzero3 ( t_ns_shifr * const ns_shifrp ,
  shifr_arrps arrpsp ) {
  uint8_t result  = 0 ;
  uint8_t * output_buffer = &((*  arrpsp  . p)[0]) ;
  if  ( ns_shifrp -> bitscount ==  0 )
    goto  lbreak ;
  if  ( ns_shifrp -> bitscount ==  1 )
    ns_shifrp -> secretdata [ 0 ] = ns_shifrp -> secretdata [ 3 ] ;
  else
    ns_shifrp -> secretdata [ 0 ] = ns_shifrp -> secretdata [ 2 ] ;
  datasole3 ( ns_shifrp , ( shifr_arrcp ) & ns_shifrp -> secretdata ,
    & ns_shifrp -> secretdatasole , 1 )  ;
  uint8_t secretdatasolesize  = 1 ;  
  // после подсоления, данные переворачиваем предыдущим ксором
  data_xor3 ( & ns_shifrp -> old_last_data , & ns_shifrp -> old_last_sole ,
    & ns_shifrp -> secretdatasole , secretdatasolesize )  ;
  uint8_t encrypteddata [ 3 ] ;
  crypt_decrypt ( & ns_shifrp -> secretdatasole , ( shifr_arrcp ) & ns_shifrp  -> shifr3 ,
    & encrypteddata , secretdatasolesize ) ;
  
  size_t  writes  = 0 ;
  streambuf_write3 ( ns_shifrp , & ns_shifrp -> filebufto ,
    ( uint8_t const ( * ) [ 3 ] ) & encrypteddata ,
    secretdatasolesize , ns_shifrp  -> flagtext , & output_buffer , & writes ,
    arrpsp . s )  ;
  ++  result  ;

lbreak  : ;

  t_streambuf * const me = & ns_shifrp ->  filebufto ;

  if  ( me -> bufbitsize ) {
    ( * output_buffer ) = me -> buf ;
    ++  output_buffer ;
    ++  result  ;
    me -> bufbitsize = 0 ; }

  if ( ns_shifrp  -> flagtext and ( me -> bytecount ) )  {
    me -> bytecount = 0 ;
    ( * output_buffer ) = '\n' ;
    ++  output_buffer ;
    ++  result  ; }
  return  result  ; }

// версия 3 пишу три бита для расшифровки
// version 3 write three bits to decode
void  streambuf_write3bits ( t_ns_shifr * const ns_shifrp ,
  uint8_t const encrypteddata , uint8_t * restrict * const output_bufferp ,
  size_t * const writesp ) {
  t_streambuf * const restrict me  = & ns_shifrp -> filebufto  ;
  if  ( ( me -> bufbitsize ) < 5 ) {
    me -> buf = ( uint8_t ) ( ( me -> buf ) bitor
      ( encrypteddata <<  ( me -> bufbitsize ) ) ) ;
    me -> bufbitsize = ( uint8_t ) ( ( me -> bufbitsize ) + 3U ) ; }
  else  {
    uint8_t const to_write  = ( uint8_t ) ( ( encrypteddata   << (
      me -> bufbitsize ) ) bitor ( me -> buf ) ) ;
    ( * * output_bufferp ) = to_write  ;
    ++  ( * output_bufferp  ) ;
    ++  ( * writesp ) ;
    // + 3 - 8
    me -> bufbitsize = ( uint8_t ) ( ( me -> bufbitsize ) - 5U ) ;
    me -> buf =  ( uint8_t ) ( encrypteddata   >>
      ( 3 - ( me -> bufbitsize ) ) ) ; } }

static inline void  data_xor2  ( t_ns_shifr * const ns_shifrp ,
  shifr_arrp  const secretdatasole  , size_t  const data_size ) {
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ 0 ] ) ;
  do {
    uint8_t const cur_data = ( * ids ) >> 2 ;
    uint8_t const cur_sole = ( * ids ) bitand 0x3 ;
    // главное данные , хвост - соль : 01 =>
    //   01_00 или 01_01 или 01_10 или 01_11
    // в таблице всё рядом, 4 варианта равномерно распределены
    // данные сыпью предыдущей солью
    ( * ids ) = ( uint8_t ) ( ( * ids ) xor ( ( ns_shifrp -> old_last_sole ) << 2  ) ) ;
    ( * ids ) xor_eq  ( ns_shifrp -> old_last_data ) ;
    // беру свежую соль
    ns_shifrp -> old_last_sole = cur_sole ;
    ns_shifrp -> old_last_data = cur_data ;
    ++  ids ;
  } while ( ids not_eq & ( ( * secretdatasole ) [ data_size ] ) ) ; }

// returns size loads & writes
shifr_size_io shifr_encrypt2  ( t_ns_shifr * const ns_shifrp , shifr_arrcps const input ,
  shifr_arrps const output  ) {
  uint8_t const * restrict  input_buffer = &((* input . cp)[0]) ;
  uint8_t * restrict  output_buffer = &((*  output  . p)[0]) ;
  size_t  reads = 0 ;
  size_t  writes  = 0 ;
  while ( reads < input . s and writes + 4 <= output . s ) {
    char const  buf = ( char ) ( * input_buffer ) ;
    ++  input_buffer  ;
    ++  reads ;
    uint8_t const secretdata  [ 4 ] = { [ 0 ]  = buf  bitand 0x3 ,
      [ 1 ] = ( buf >>  2 ) bitand 0x3 , [ 2 ] = ( buf >>  4 ) bitand 0x3 ,
      [ 3 ] = ( buf >>  6 ) bitand 0x3 } ;
    uint8_t secretdatasole  [ 4 ] ;
    datasole2 ( ns_shifrp , & secretdata , & secretdatasole , 4 )  ;
    // после подсоления, данные переворачиваем предыдущим ксором
    data_xor2 ( ns_shifrp , & secretdatasole , 4 )  ;
    uint8_t encrypteddata [ 4 ] ;
    crypt_decrypt ( & secretdatasole , ( shifr_arrcp ) & ns_shifrp  -> shifr2 ,
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
      uint16_t  buf16 = ( uint16_t  ) (
        ( ( uint16_t  ) ( encrypteddata [ 0 ] bitand  0xf ) ) bitor
        ( ((uint16_t)( encrypteddata [ 1 ] bitand 0xf )) << 4  )  bitor
        ( ((uint16_t)( encrypteddata [ 2 ] bitand 0xf )) << 8  )  bitor
        ( ((uint16_t)( encrypteddata [ 3 ] bitand 0xf )) << 12  )) ;
      char buf3 [ 4 ] ;
      buf3 [ 0 ] = (  char  ) ( 'R' + ( buf16 % 40 ) ) ;
      buf16 /= 40 ;
      buf3 [ 1 ] = (  char  ) ( 'R' + ( buf16 % 40 ) ) ;
      buf16 /= 40 ;
      buf3 [ 2 ] = (  char  ) ( 'R' + buf16 ) ;
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
        [ 0 ] = ( char  ) ( ( ( uint16_t  ) ( encrypteddata [ 0 ] & 0xf )) bitor
          ( ((uint16_t)( encrypteddata [ 1 ] & 0xf )) << 4  ) ) ,
        [ 1 ] = ( char  ) ( ( ( uint16_t)( encrypteddata [ 2 ] & 0xf )) bitor
          ( ((uint16_t)( encrypteddata [ 3 ] & 0xf )) << 4 )  ) } ;
      memcpy  ( output_buffer , & ( buf2 [ 0 ] )  , 2 ) ;
      writes  +=  2 ;
      output_buffer +=  2 ; } }
  return  ( shifr_size_io ) { .i  = reads , .o  = writes  } ; }

/*
Finished buffer encryption, returns output_buffer size written
Заканчивает шифрование буфера, возвращает размер записаных данных.
*/
size_t  shifr_encrypt2_flush  ( t_ns_shifr * const ns_shifrp ,
  shifr_arrps const output ) {
# ifdef SHIFR_DEBUG
  if ( output . s == 0 ) {
    ns_shifrp ->  string_exception  = ( shifr_strcp ) &
      "shifr_encrypt2_flush:output . s == 0" ;
    longjmp ( ns_shifrp ->  jump  , 1 ) ; }
# endif // SHIFR_DEBUG
  if ( ns_shifrp  -> flagtext and ns_shifrp  -> charcount ) {
    ns_shifrp  -> charcount = 0 ;
    ( * output . p ) [ 0 ] = '\n' ;
    return  1 ; }
  return  0 ; }

// returns size loads & writes
shifr_size_io shifr_encrypt3  ( t_ns_shifr * const ns_shifrp , shifr_arrcps const input ,
  shifr_arrps const output  ) {
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
    switch  ( ns_shifrp -> bitscount  ) {
    case  0 :
        // <= [ [1 0] [2 1 0] [2 1 0] ]
        ( ns_shifrp -> secretdata ) [ 0 ]  = buf  bitand 0x7 ;
        ( ns_shifrp -> secretdata ) [ 1 ] = ( buf >>  3 ) bitand 0x7 ;
        ( ns_shifrp -> secretdata ) [ 2 ] = buf >>  6 ;
        ns_shifrp -> bitscount  = 2 ; // 0 + 8 - 6
        secretdatasolesize  = 2 ;
        break ;
    case  1 : 
        // <= [ [2 1 0] [2 1 0] [2 1] ] <= [ [0]
        ( ns_shifrp -> secretdata ) [ 0 ] = ( uint8_t ) (
          ( ns_shifrp -> secretdata ) [ 3 ] bitor
          (( buf  bitand 0x3 )<<1)) ;
        ( ns_shifrp -> secretdata ) [ 1 ] = ( buf >>  2 ) bitand 0x7 ;
        ( ns_shifrp -> secretdata ) [ 2 ] = buf >>  5 ;
        ns_shifrp -> bitscount  = 0 ;   // 1 + 8 - 9
        secretdatasolesize  = 3 ;
        break ;
    case  2 :
        // <= [ [0] [2 1 0] [2 1 0] [2] ] <= [ [1 0] ..
        ( ns_shifrp -> secretdata ) [ 0 ] = ( uint8_t ) (
          ( ns_shifrp -> secretdata ) [ 2 ] bitor
          (( buf  bitand 0x1 )<<2) ) ;
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
        ( shifr_strcp ) & u8"неожиданное значение bitscount" :
        ( shifr_strcp ) & "unexpected value bitscount" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; } // switch  ( ns_shifrp -> bitscount  )
    datasole3 ( ns_shifrp , ( shifr_arrcp ) & ( ns_shifrp -> secretdata ) ,
      & ns_shifrp -> secretdatasole , secretdatasolesize )  ;
    // после подсоления, данные переворачиваем предыдущим ксором
    data_xor3 ( & ns_shifrp -> old_last_data , & ns_shifrp -> old_last_sole ,
      & ns_shifrp -> secretdatasole , secretdatasolesize )  ;
    crypt_decrypt ( & ns_shifrp -> secretdatasole ,
      ( shifr_arrcp ) & ns_shifrp  -> shifr3 , & encrypteddata , secretdatasolesize ) ;
    streambuf_write3 ( ns_shifrp , & ns_shifrp -> filebufto ,
      ( uint8_t const ( * ) [ 3 ] ) & encrypteddata ,
      secretdatasolesize , ns_shifrp  -> flagtext , & output_buffer , & writes ,
      output . s ) ; } // while
  return ( shifr_size_io ) { .i  = reads , .o  = writes  }  ; }

# define  decrypt_sole2  shifr_decrypt_sole2
static inline void  decrypt_sole2 ( shifr_arrp const datap , shifr_arrcp const tablep ,
  shifr_arrp const decrp , size_t const data_size ,
  uint8_t * const restrict old_last_sole ,
  uint8_t * const restrict old_last_data ) {
  uint8_t const * restrict  id = & ( ( * datap ) [ 0 ] ) ;
  uint8_t * restrict  ide = & ( ( * decrp ) [ 0 ] ) ;
  do {
    { uint8_t const data_sole = ( * tablep ) [ * id ] ;
      ( * ide ) = ( data_sole >>  2 ) xor ( * old_last_sole ) ;
      ( * old_last_sole ) = ( uint8_t ) (
        (  data_sole bitand  0x3 ) xor ( * old_last_data ) ) ; }
    ( * old_last_data ) = ( * ide ) ;
    ++  id  ;
    ++  ide ;
  } while ( id not_eq & ( ( * datap ) [ data_size ] ) ) ; }

// returns size loads & writes
shifr_size_io  shifr_decrypt2  ( t_ns_shifr * const ns_shifrp , shifr_arrcps const input ,
  shifr_arrps const output  ) {
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
          ( ns_shifrp  -> buf2 ) [ ns_shifrp  -> buf2index ] =
            (  char  ) ( * input_buffer ) ;
          ++  input_buffer  ;
          ++  reads ;
        } while ( ( ns_shifrp  -> buf2 ) [ ns_shifrp  -> buf2index ] < 'R' or
          ( ns_shifrp  -> buf2 ) [ ns_shifrp  -> buf2index ] > 'z' ) ;
        ++ ( ns_shifrp  -> buf2index ) ;
      } while ( ns_shifrp  -> buf2index < 3 ) ;
      // next letters begins with zero index
      // следующие буквы начинают с нулевого индекса
      ns_shifrp  -> buf2index = 0 ;
      uint16_t u16 = ( uint16_t ) (
        ( ( uint16_t  ) ( ( ns_shifrp  -> buf2 ) [ 0 ] - 'R' ) ) +
        40U * ( ( ( uint16_t  ) ( ( ns_shifrp  -> buf2 ) [ 1 ] - 'R' ) ) +
        40U * ( ( uint16_t  ) ( ( ns_shifrp  -> buf2 ) [ 2 ] - 'R' ) ) ) ) ;
      buf [ 0 ] = ( char ) ( u16 bitand 0xff ) ;
      buf [ 1 ] = ( char  ) ( u16 >> 8  ) ; } // flagtext
    else {
      if ( reads + 1 >= input . s )
        goto Exit ;
      buf [ 0 ] = ( char  ) ( * input_buffer ) ;
      ++  input_buffer  ;
      ++  reads ;
      buf [ 1 ] = ( char  ) ( * input_buffer ) ;
      ++  input_buffer  ;
      ++  reads ; } // flag digit
    uint8_t secretdata  [ 4 ] = { [ 0 ] = buf [ 0 ] bitand  0xf ,
      [ 1 ] = ( buf [ 0 ] >>  4 ) bitand  0xf ,
      [ 2 ] = buf [ 1 ] bitand  0xf ,
      [ 3 ] = ( buf [ 1 ] >>  4 ) bitand  0xf  } ;
    uint8_t decrypteddata [ 4 ] ;
    decrypt_sole2 ( & secretdata , ( shifr_arrcp ) & ( ns_shifrp  -> deshi2 ) ,
      & decrypteddata , 4 , & ns_shifrp  -> old_last_sole ,
      & ns_shifrp  -> old_last_data ) ;
    ( * output_buffer ) = ( uint8_t ) ( ( decrypteddata [ 0 ] bitand 0x3  ) bitor
      ( ( decrypteddata [ 1 ] bitand 0x3  ) << 2  )
      bitor ( ( decrypteddata [ 2 ] bitand 0x3  ) <<  4 ) bitor
      ( ( decrypteddata [ 3 ] bitand 0x3  ) << 6  ) ) ;
    ++  writes  ;
    ++  output_buffer ; }
Exit :
  return  ( shifr_size_io ) { .i  = reads , .o  = writes  } ; }

# define  decrypt_sole3  shifr_decrypt_sole3
static inline void  decrypt_sole3 ( shifr_arrp const datap , shifr_arrcp const tablep ,
  shifr_arrp const decrp , size_t const data_size ,
  uint8_t * const restrict old_last_sole ,
  uint8_t * const restrict old_last_data ) {
  uint8_t const * restrict  id = & ( ( * datap ) [ 0 ] ) ;
  uint8_t * restrict  ide = & ( ( * decrp ) [ 0 ] ) ;
  do {
    { uint8_t const data_sole = ( * tablep ) [ * id ] ;
      ( * ide ) = ( data_sole >>  3 ) xor ( * old_last_sole ) ;
      ( * old_last_sole ) = ( uint8_t ) (
        ( data_sole bitand  0x7 ) xor ( * old_last_data ) ) ;
      ( * old_last_data ) = ( * ide ) ; }
    ++  id  ;
    ++  ide ;
  } while ( id not_eq & ( ( * datap ) [ data_size ] ) ) ; }

shifr_size_io shifr_decrypt3 ( t_ns_shifr * const ns_shifrp , shifr_arrcps const input ,
  shifr_arrps const output ) {
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
    decrypt_sole3 ( & secretdata , ( shifr_arrcp ) & ns_shifrp  -> deshi3 , &
      decrypteddata , 1 , & ns_shifrp  -> old_last_sole , & ns_shifrp  -> old_last_data
      ) ;
    streambuf_write3bits ( ns_shifrp , decrypteddata [ 0 ] , & output_buffer ,
      & writes ) ; } // while
  return  ( shifr_size_io ) { . i  = reads , .  o  = writes  } ; }

# undef streambuf_bufbitsize

// inits array [ 0..15 , 0..14 , ... , 0..2 , 0..1 ]
void  shifr_generate_pass2 ( t_ns_shifr * const ns_shifrp ) {
  uint8_t * j = & ( ns_shifrp -> raspr2  . dice [ 0 ] ) ;
  uint8_t i  = 0x10 - 1 ; // 15
  do {
    ( * j ) = ( uint8_t ) uirandfrto  ( ns_shifrp , 0 , i ) ;
    -- i  ;
    ++ j  ;
  } while ( i >= 1 ) ; }

// inits array [ 0..63 , 0..62 , ... , 0..2 , 0..1 ]
void  shifr_generate_pass3 ( t_ns_shifr * const ns_shifrp ) {
  uint8_t * j = & ( ns_shifrp -> raspr3  . dice [ 0 ] ) ;
  uint8_t i  = 0x40 - 1 ; // 63
  do {
    ( * j ) = ( uint8_t ) uirandfrto  ( ns_shifrp , 0 , i ) ;
    -- i  ;
    ++ j  ;
  } while ( i >= 1 ) ; }

// [ 0..15 , 0..14 , 0..13 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ] =
// = x + y * 16 + z * 16 * 15 + ... + u * 16! / 2 / 3 + v * 16! / 2 = 0 .. 16!-1
void  shifr_pass_to_array2 ( t_ns_shifr * const ns_shifrp ) {
  number_set0 ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ) ;
  number_priv_type ( v2 ) mu  ;
  number_set_byte ( v2 ) ( & mu . pub , 1 ) ;
  uint8_t in = 0 ;
  do {
    { number_priv_type ( v2 ) mux = mu ;
      // re += dice [ in ] * mu ;
      number_mul_byte ( v2 ) ( & mux . pub ,
        ns_shifrp -> raspr2  . dice [ in ] ) ;
      number_add  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
        & mux . pub ) ; }
    //$mu *=  16 - $in ;
    number_mul_byte ( v2 ) ( & mu . pub , ( uint8_t ) ( 0x10 - in ) ) ;
    ++  in ;
  } while ( in < 0x10 - 1 ) ; }

// [ 0..63 , 0..62 , 0..61 , ... , 0..2 , 0..1 ] = [ x , y , z , ... , u , v ] =
// = x + y * 64 + z * 64 * 63 + ... + u * 64! / 2 / 3 + v * 64! / 2 = 0 .. 64!-1
void  shifr_pass_to_array3 ( t_ns_shifr * const ns_shifrp ) {
  number_set0 ( number_size3 ) ( & ns_shifrp -> raspr3  . pass . pub ) ;
  number_priv_type ( number_size3 ) mu  ;
  number_set_byte ( number_size3 ) ( & mu . pub , 1 ) ;
  uint8_t in = 0 ;
  do {
    { number_priv_type ( number_size3 ) mux = mu ;
      // re += dice [ in ] * mu ;
      number_mul_byte ( number_size3 ) (
        & mux . pub ,  ns_shifrp -> raspr3  . dice [ in ] ) ;
      number_add  ( number_size3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
        & mux . pub ) ; }
    //$mu *=  64 - $in ;
    number_mul_byte ( number_size3 ) ( & mu . pub , ( uint8_t ) ( 0x40 - in ) ) ;
    ++  in ;
  } while ( in < 0x40 - 1 ) ; }

# ifdef SHIFR_DEBUG

# define  shifr_number_def_princ( N , D ) \
void  shifr_number  ##  N ##  _princ ( shifr_number_type ( N ) const * const np ,  \
  FILE * const fs ) { \
  fputs ( "[ " , fs ) ; \
  uint8_t i = D ;  \
  do {  \
    -- i ;  \
    fprintf ( fs  , "%x , " , number_elt_copy ( N ) ( np , i ) ) ;  \
  } while ( i ) ; \
  fputs ( "]" , fs ) ; }
# define  number_def_princ shifr_number_def_princ

number_def_princ  ( v2 , shifr_number_size2 )
number_def_princ  ( number_size3 , number_size3 )

# endif // SHIFR_DEBUG

void  string_to_password ( t_ns_shifr * const ns_shifrp ) {
  switch ( ns_shifrp -> use_version ) {
  case 2 :
    switch  ( ns_shifrp -> password_alphabet  ) {
    case  letters_count :
      string_to_password_templ  ( v2 ) ( ns_shifrp ,
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters2 ,
        & ns_shifrp -> raspr2  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters ,  letters_count ) ;
      break ;
    case  letters_count2  :
      string_to_password_templ  ( v2 ) ( ns_shifrp ,
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters2 ,
        & ns_shifrp -> raspr2  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters2 , letters_count2 ) ;
      break ;
    case  letters_count3  :
      string_to_password_templ  ( v2 ) ( ns_shifrp ,
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters2 ,
        & ns_shifrp -> raspr2  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters3 , letters_count3 ) ;
      break ;
    case  letters_count4  :
      string_to_password_templ  ( v2 ) ( ns_shifrp ,
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters2 ,
        & ns_shifrp -> raspr2  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters4 , letters_count4 ) ;
      break ;
    default :
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) & u8"string_to_password : версия алфавита не известна" :
        ( shifr_strcp ) & "string_to_password : alphabet version is not known" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
    break ;
  case 3 :
    switch  ( ns_shifrp -> password_alphabet  ) {
    case  letters_count :
      string_to_password_templ  ( number_size3 ) ( ns_shifrp ,
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters3 ,
        & ns_shifrp -> raspr3  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters ,  letters_count ) ;
      break ;
    case  letters_count2  :
      string_to_password_templ  ( number_size3 ) ( ns_shifrp , 
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters3 ,
        & ns_shifrp -> raspr3  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters2 , letters_count2 ) ;
      break ;
    case  letters_count3  :
      string_to_password_templ  ( number_size3 ) ( ns_shifrp , 
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters3 ,
        & ns_shifrp -> raspr3  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters3 , letters_count3 ) ;
      break ;
    case  letters_count4  :
      string_to_password_templ  ( number_size3 ) ( ns_shifrp , 
        ( shifr_strvcp  ) & ns_shifrp  -> password_letters3 ,
        & ns_shifrp -> raspr3  . pass . pub ,
        ( shifr_strcp ) & ns_shifrp -> letters4 , letters_count4 ) ;
      break ;
    default :
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) & u8"string_to_password : версия алфавита не известна" :
        ( shifr_strcp ) & "string_to_password : alphabet version is not known" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
    break ;
  default :
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      u8"string_to_password : версия %d не поддерживается\n" :
      "string_to_password : version %d is not supported" ) ,
      ns_shifrp -> use_version )  ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & u8"string_to_password : версия не поддерживается" :
      ( shifr_strcp ) & "string_to_password : version is not supported" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; } }

# define  initarr shifr_initarr
static inline  void  initarr ( shifr_arrp  const p , uint8_t const codefree ,
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

# define  shifr_password_load( N ) shifr_password_  ##  N ##  _load
# define  password_load shifr_password_load

# define  shifr_password_load_def(  N , SDS ) \
void  password_load ( N ) ( shifr_number_type ( N ) const * const password0 , \
  shifr_arrp const shifrp , shifr_arrp const deship ) { \
  initarr ( shifrp  , 0xff  , SDS ) ; \
  initarr ( deship  , 0xff  , SDS ) ; \
  uint8_t volatile  arrind  [ SDS ] ; \
  { uint8_t volatile  * arrj  = & ( arrind  [ SDS  ] ) ;  \
    uint8_t j = SDS  ;  \
    do  { \
      --  arrj  ; \
      --  j ; \
      ( * arrj )  = j ; \
    } while ( arrj  not_eq & ( arrind  [ 0 ] ) ) ;  } \
  uint8_t inde  = 0 ; \
  number_priv_type ( N ) password = * number_const_pub_to_priv ( N ) ( password0 ) ; \
  do {  \
    { uint8_t const cindex = number_div_mod ( N ) ( & password . pub ,  \
        (  uint8_t ) ( SDS - inde  ) ) ;  \
      uint8_t volatile  * const arrind_cindexp = & (  arrind [ cindex ] ) ; \
      ( * shifrp ) [ inde ] = ( * arrind_cindexp ) ;  \
      ( * deship ) [ * arrind_cindexp ] = inde ;  \
      memmove ( ( uint8_t * ) arrind_cindexp , ( uint8_t * ) arrind_cindexp + 1 , \
        ( size_t  ) ( SDS  - inde  - cindex - 1 ) ) ; } \
    ++ inde  ;  \
  } while ( inde < SDS ) ; \
  memsetv ( arrind  , memsetv_default_char  , sizeof  ( arrind  ) ) ; }

static  inline  shifr_password_load_def (  v2 , shifr_deshi_size2 )
static  inline  shifr_password_load_def (  number_size3 , shifr_deshi_size3 )

void  password_load_uni ( t_ns_shifr * const ns_shifrp ) {
  switch ( ns_shifrp -> use_version )  {
  case 2 :
    password_load ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
      & ns_shifrp  -> shifr2 , & ns_shifrp  -> deshi2 ) ;
    break ;
  case 3 :
    password_load ( number_size3 ) ( & ns_shifrp -> raspr3  . pass . pub , 
      & ns_shifrp  -> shifr3 , & ns_shifrp  -> deshi3 ) ;
    break ;
  default :
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      u8"password_load:версия %d не поддерживается\n" :
      "password_load:version %d is not supported" ) , ns_shifrp -> use_version )  ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & u8"password_load:версия не поддерживается" :
      ( shifr_strcp ) & "password_load:version is not supported" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; } }

void  password_to_string  ( t_ns_shifr * const ns_shifrp ) {
  switch  ( ns_shifrp -> use_version ) {
  case  2 :
    switch  ( ns_shifrp -> password_alphabet  ) {
    case  letters_count :
      password_to_string_templ  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
        & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters ,
        letters_count ) ;
      break ;
    case  letters_count2  :
      password_to_string_templ  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
        & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters2 ,
        letters_count2 ) ;
      break ;
    case  letters_count3  :
      password_to_string_templ  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
        & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters3 ,
        letters_count3 ) ;
      break ;
    case  letters_count4  :
      password_to_string_templ  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
        & ns_shifrp  -> password_letters2 , & ns_shifrp -> letters4 ,
        letters_count4 ) ;
      break ;
    default :
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) & u8"password_to_string:версия алфавита не известна" :
        ( shifr_strcp ) & "password_to_string:alphabet version is not known" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
    break ;
  case 3 :
    switch  ( ns_shifrp -> password_alphabet  ) {
    case  letters_count :
      password_to_string_templ  ( number_size3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
        & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters ,
        letters_count ) ;
      break ;
    case  letters_count2  :
      password_to_string_templ  ( number_size3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
        & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters2 ,
        letters_count2 ) ;
      break ;
    case  letters_count3  :
      password_to_string_templ  ( number_size3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
        & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters3 ,
        letters_count3 ) ;
      break ;
    case  letters_count4  :
      password_to_string_templ  ( number_size3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
        & ns_shifrp  -> password_letters3 , & ns_shifrp -> letters4 ,
        letters_count4 ) ;
      break ;
    default :
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) & u8"password_to_string:версия алфавита не известна" :
        ( shifr_strcp ) & "password_to_string:alphabet version is not known" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
    break ;
  default :
    fprintf ( stderr  , ( ns_shifrp -> localerus ?
      u8"password_to_string:версия %d не поддерживается\n" :
      "password_to_string:version %d is not supported" ) ,
      ns_shifrp -> use_version )  ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & u8"password_to_string:версия не поддерживается" :
      ( shifr_strcp ) & "password_to_string:version is not supported" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; } }
  
void  volatile  * memsetv ( void  volatile  * const str , uint8_t const ch  ,
  size_t  n ) {
  uint8_t volatile  * p = str ;
  while ( n ) {
    * p = ch  ;
    --  n ;
    ++  p ; }
  return  str ; }

void  shifr_destr ( t_ns_shifr * const ns_shifrp ) {
  memsetv ( ns_shifrp ->  password_letters2 , memsetv_default_char  ,
    sizeof  ( ns_shifrp ->  password_letters2 ) ) ;
  memsetv ( ns_shifrp ->  password_letters3 , memsetv_default_char  ,
    sizeof  ( ns_shifrp ->  password_letters3 ) ) ; }
