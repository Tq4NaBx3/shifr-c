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
// RAND_MAX размер 31 бит
// первый рандом 22/31 , второй 23/31 
// максимальный рандом < [ 2494190 , 7700480 ] =
//   2494190 * ( 2 ^ 23 ) + 7700480 == 20922789888000

/*
Соль одного элемента будет ксорить следующий элемент для исчезания повторов.
Если все элементы будут одного значения, тогда все шифрованные значения будут иметь свойство псевдо-случайности.
И данные и соль имеют секретность кроме первой нулевой соли.
Функция Шифр(пары: данные+соль) должна быть случайной неупорядоченной.

Файл с нулевыми данными.

Данные :       00⊻00=00 00⊻10=10 00⊻01=01  ...
           ______/  ______/  ______/  ______/
Соль   : 00       10       01       11
    
Шифр   :       S(0010)  S(1001)  S(0111)

Для расшифровки требуется ксорить данные с предыдущей солью.

Шифр   :      R(0010)  R(1001)   R(0111)

Соль   : 00     10        01        11
            \        \         \
Данные :     00⊻00=00  10⊻10=00  01⊻01=00  ...

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
// RAND_MAX size 31 bits
// first random 22/31 , second 23/31 
// maximum random < [ 2494190 , 7700480 ] =
//   2494190 * ( 2 ^ 23 ) + 7700480 == 20922789888000

/*
The salt of one element will modify (xor) the next element to remove repeats.
If all elements are of the same value, then all encrypted values will have the property of pseudo-randomness.
Both data and salt have secrecy apart from the first zero salt.
Function Shifr(of pair: data+salt)should be randomly disordered.

File with zero data.

Data   :       00⊻00=00 00⊻10=10 00⊻01=01  ...
           ______/  ______/  ______/  ______/
Salt   : 00       10       01       11
    
Shifr  :       S(0010)  S(1001)  S(0111)

To decrypt, you need to modify (xor) the data with the previous salt.

Shifr  :      R(0010)  R(1001)   R(0111)

Salt   : 00     10        01        11
            \        \         \
Data   :     00⊻00=00  10⊻10=00  01⊻01=00  ...

*/

// Version 6

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
// RAND_MAX размер 31 бит нужно десять рандомов 10*31=310
// минус 14 бит 10*31-14=296
// 29/31 29/31 29/31 29/31 30/31 30/31 30/31 30/31 30/31 30/31
//(nil let ((n (64 !)))
//   (6 for* i
//      (cout print n)
//      (cout print "% = " (n % (2 ^ 30)))
//      ('n set (n  floor (2 ^ 30))))
//   (4 for* i
//      (cout print n)
//      (cout print "% = "  (n % (2 ^ 29)))
//      ('n set (n  floor (2 ^ 29)))))
// максимальный рандом < [ 535066862 , 110135612 , 525642490 , 78362151 , 
//   851424078 , 36645132 , 465456948 , 371982424 , 0 , 0 ]

# include <locale.h>
# include <stdio.h>
# include <stdint.h>
# include <stdlib.h>
# include <time.h>
# include <iso646.h>
# include <stdbool.h>
# include <string.h>
# include <errno.h>
# include <termios.h>
# include <setjmp.h>

# define  SHIFR_DEBUG

typedef uint8_t ( * arrp ) [ ] ;
typedef uint8_t const ( * arrcp ) [ ] ;
typedef char ( * strp ) [ ] ;
typedef char const ( * strcp ) [ ] ;

// четыре * четыре = шестнадцать
# define  shifr_deshi_size2  ((size_t)(0x10U))

// 8 * 4 = 32
# define  shifr_deshi_size5  ((size_t)(0x20U))

// 8 * 8 = 64
//# define  shifr_deshi_size4  ((size_t)(0x40U))

static  void  initarr ( arrp  const p , uint8_t const codefree ,
  size_t loc_shifr_deshi_size ) {
  uint8_t * i = & ( ( * p ) [ loc_shifr_deshi_size  ] ) ;
  do {
    --  i ;
    ( * i ) = codefree ;
  } while ( i not_eq  & ( ( * p ) [ 0 ] ) ) ; }
  
# ifdef SHIFR_DEBUG
static  void  printarr  ( strcp const  name , arrcp const p ,
  size_t const arrsize ) {
  printf  ( u8"%s = [ " , * name  ) ;
  uint8_t const * i = & ( ( * p ) [ 0 ] ) ;
  do {
    printf  ( "%x , " , ( int ) ( * i ) ) ; 
    ++  i ;
  } while ( i not_eq  & ( ( * p ) [ arrsize ] ) ) ;
  puts ( u8"]" ) ; }
# endif

static  void  crypt_decrypt ( arrp const datap , arrcp const tablep ,
  arrp const encrp , size_t const data_size ) {
  uint8_t const * id = & ( ( * datap ) [ data_size ] ) ;
  uint8_t * ied = & ( ( * encrp ) [ data_size ] ) ;
  do {
    -- id ;
    --  ied ;
    ( * ied ) = ( * tablep ) [ * id ] ;
  } while ( id not_eq & ( ( * datap ) [ 0 ] ) ) ; }
  
static  void  decrypt_sole ( arrp const datap , arrcp const tablep ,
  arrp const decrp , size_t const data_size ,
  uint8_t * const restrict old_last_sole ) {
  uint8_t const * restrict  id = & ( ( * datap ) [ 0 ] ) ;
  uint8_t * restrict  ide = & ( ( * decrp ) [ 0 ] ) ;
  do {
    { uint8_t const data_sole = ( * tablep ) [ * id ] ;
      ( * ide ) = ( data_sole >>  2 ) xor ( * old_last_sole ) ;
      ( * old_last_sole ) = data_sole bitand  0x3 ; }
    ++  id  ;
    ++  ide ;
  } while ( id not_eq & ( ( * datap ) [ data_size ] ) ) ; }

// указатель на массив разной длины
# define  t_type_raspr_xp(  N )  \
  typedef uint8_t ( * type_raspr##N##_xp  ) [ ] [ N ] ;
  
t_type_raspr_xp ( 4 )
//t_type_raspr_xp ( 8 )

# define  type_raspr_xp(  N ) type_raspr##N##_xp

# define  raspr4_32_size (UINT16_C(35960))
# define  raspr4_28_size (UINT16_C(20475))
# define  raspr4_24_size (UINT16_C(10626))
# define  raspr4_20_size (UINT16_C(4845))
# define  raspr4_16_size (UINT16_C(43680))
# define  raspr4_12_size (UINT16_C(11880))
# define  raspr4_8_size (UINT16_C(1680))
# define  raspr4_4_size (UINT8_C(24))

// 0x20 (пробел) ' '    ---     0x7e (тильда) '~'
// 95 шт
# define letters_count (UINT8_C(('~' - ' ') + 1))

// 0x30 '0' - 0x39 '9' , 0x41 'A' - 0x5a 'Z' , 0x61 'a' - 0x7a 'z'
// 62 шт
# define letters_count2 (UINT8_C( \
  ('9' - '0') + 1 + ('Z' - 'A') + 1 + ('z' - 'a') + 1 ))

struct  s_raspr4 {

uint64_t  password_const  ;

} ;

typedef struct  s_number128 {
  uint64_t a [ 2 ] ;
} t_number128 ;

typedef struct  s_number96 {
  uint32_t a  [ 3 ] ;
} t_number96 ;

struct  s_raspr5 {

// массив размеров разных распределений
uint16_t  s [ 8 ] ;
  
// 8 указателей на  массивы разных распределений ( 4х штучных )
type_raspr_xp ( 4 )  xp  [ 8 ] ;
 
// live
bool  gTNb  ;

t_number128  password_const  ;

} ;

typedef struct  s_number320 {
  uint64_t a [ 5 ] ;
} t_number320 ;

struct  s_raspr6 {

t_number320 password_const  ;

} ;

# define  isLive5namepub gTNb
# define  isLive5namepri "live is private"
# define  isLive5name isLive5namepri
# define  isLive5pub(  R ) ((R)->gTNb)
# define  isLive5pro(  R ) ((bool const)((R)->gTNb))
# define  isLive5pri(  R ) "live is private"
# define  isLive5 isLive5pro

struct  s_ns_shifr  {

// буквы разрешённые в пароле :
// ascii  
char  letters [ letters_count ] ;  
// a..zA..Z0..9
char  letters2 [ letters_count2 ] ;    
bool  localerus ; 

// хранилище дефолтного состояния
struct termios stored_termios  ;

// исключения
jmp_buf jump ;
char const (  * string_exception  ) [ ] ;

struct  s_raspr4 raspr4 ;
struct  s_raspr5 raspr5 ;
struct  s_raspr6 raspr6 ;

int use_version ; //  4 или 5 или 6

} ;

# undef isLive5name
# define  isLive5name isLive5namepub

static  struct  s_ns_shifr  ns_shifr = {
  .raspr5 = {
    .s = { [ 7 ] = raspr4_32_size , [ 6 ] = raspr4_28_size ,
      [ 5 ] = raspr4_24_size , [ 4 ] = raspr4_20_size ,
      [ 3 ] = raspr4_16_size , [ 2 ] = raspr4_12_size ,
      [ 1 ] = raspr4_8_size , [ 0 ] = raspr4_4_size } ,
    . isLive5name = false ,
    } ,
  . use_version  = 4 ,
} ;

# undef isLive5name
# define  isLive5name isLive5namepri

static  void  password_to_string_uni ( uint64_t password , strp const string ,
  char (  * letters ) [ ] , uint8_t  letterscount ) {
  char * stringi = & ( ( * string )  [ 0 ] ) ;
  if ( password ) {
    while ( true ) {
      // здесь предыдущие размеры заняли место паролей
      --  password  ;
      ( * stringi ) = ( * letters ) [ password % (uint64_t)letterscount ] ;
      ++  stringi ;
      if ( password < (uint64_t)letterscount ) break ;
      password /= (uint64_t)letterscount ; } }
  ( * stringi ) = '\00' ; }
    
// number /= div , number := floor [ деление ] , return := остаток
uint8_t  number128_div8mod  ( t_number128 * restrict const number ,
  uint8_t const div ) {
  uint8_t ost = number  ->  a  [ 1 ] % ( uint64_t  ) div ;
  number  ->  a [ 1 ] /=  ( uint64_t  ) div ;
  uint64_t number05 = ( ( ( ( uint64_t  ) ost ) ) <<  56 ) bitor
    ( number  ->  a [ 0 ] >>  8 ) ;
  ost = number05 % ( uint64_t  ) div ;
  number05 /= ( uint64_t  ) div ;
  number  ->  a [ 1 ] +=  ( number05  >> 56 ) ;
  number05  <<= 8 ;
  uint16_t number00 = ( ( ost << 8 ) bitor ( number ->  a [ 0 ] bitand 0xff ) ) ;
  ost = number00 % ( uint16_t ) div ;
  number  ->  a [ 0 ] = number05 bitor ( number00 / ( uint16_t ) div ) ; 
  return  ost ; }

// number /= div , number := floor [ деление ] , return := остаток
uint16_t  number128_div16mod  ( t_number128 * restrict const number ,
  uint16_t const div ) {
  uint16_t ost = number  ->  a  [ 1 ] % ( uint64_t  ) div ;
  number  ->  a [ 1 ] /=  ( uint64_t  ) div ;
  uint64_t number05 = ( ( ( ( uint64_t  ) ost ) ) <<  48 ) bitor
    ( number  ->  a [ 0 ] >>  16 ) ;
  ost = number05 % ( uint64_t  ) div ;
  number05 /= ( uint64_t  ) div ;
  number  ->  a [ 1 ] +=  ( number05  >> 48 ) ;
  number05  <<= 16 ;
  uint32_t number00 = ( ( ((uint32_t)ost) << 16 ) bitor
    ( number ->  a [ 0 ] bitand 0xffff ) ) ;
  ost = number00 % ( uint16_t ) div ;
  number  ->  a [ 0 ] = number05 bitor ( number00 / ( uint16_t ) div ) ; 
  return  ost ; }  
  
// --
static  inline  void  number128dec  ( t_number128 * const restrict number ) {
  if ( number->a [ 0 ] ) {
    -- (  number->a [ 0 ] )  ;
    return  ; }
  -- (  number->a [ 0 ] )  ;
  -- (  number->a [ 1 ] )  ; }
  
static  inline  bool  number128_not0  (
  t_number128 const * const restrict np ) {
  return  ( ( np->a [ 0 ] ) or  ( np->a [ 1 ] ) ) ; }
  
static  void  password_to_string5_uni (
  t_number128 const * const restrict password0 , strp const string ,
  char (  * letters ) [ ] , uint8_t  letterscount  ) {
  char * stringi = & ( ( * string )  [ 0 ] ) ;
  if ( number128_not0 ( password0 ) ) {
    t_number128 password = * password0  ;
    do {
      // здесь предыдущие размеры заняли место паролей
      number128dec  ( & password  ) ;
      ( * stringi ) = ( * letters ) [ number128_div8mod  ( & password ,
        letterscount ) ] ;
      ++  stringi ;
    } while ( number128_not0 ( & password ) ) ; }
  ( * stringi ) = '\00' ;  }

static  void  string_to_password_uni ( strcp const string ,
  uint64_t * const password , char (  * letters ) [ ] , uint8_t  letterscount ) {
  char const * restrict stringi = & ( ( * string )  [ 0 ] ) ;
  if  ( ( * stringi ) == '\00' ) {
    ( * password  ) = 0 ;
    return ; }
  uint64_t  pass  = 0 ;
  uint64_t  mult  = 1 ;
  do  {
    uint8_t i = letterscount ;
    do {
      -- i ;
      if ( ( * stringi ) == ( * letters )  [ i ] ) goto found ; 
    } while ( i ) ;
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      ( char const ( * ) [ ] ) & u8"неправильная буква в пароле" :
      ( char const ( * ) [ ] ) & "wrong letter in password" ) ;
    longjmp ( ns_shifr  . jump  , 1 ) ;
found :
    pass  +=  ( ( uint64_t  ) ( i + 1 ) ) * mult ;
    mult  *=  ( uint64_t  ) letterscount ;
    ++  stringi ;
  } while ( * stringi ) ;
  ( * password ) = pass ; }
  
static  inline  void number128_set0  (
  t_number128 * const restrict np ) {
  ( * np  ) = ( t_number128 ) { { [ 0 ] = 0 , [ 1 ] = 0 } } ; }

static  inline  void number128_add  (
  t_number128 * const restrict np , t_number128 const * const restrict xp ) {
  uint64_t const old = np  ->  a [ 0 ] ;
  if ( np == xp ) {
    ( np  ->  a [ 1 ] ) <<= 1 ;
    ( np  ->  a [ 0 ] ) <<= 1 ; }
  else  {
    ( np  ->  a [ 1 ] ) +=  ( xp  ->  a [ 1 ] ) ;
    ( np  ->  a [ 0 ] ) +=  ( xp  ->  a [ 0 ] ) ; }
  if (  np  ->  a [ 0 ] < old ) ++  ( np  ->  a [ 1 ] ) ; }
  
void  number128_mul8  ( t_number128 * const restrict np , uint8_t const m ) {
  // [0]
  uint64_t r0 = ( ( ( ( np  ->  a [ 0 ] ) << 8 ) >> 8 ) * ( ( uint64_t  ) m ) ) ;
  // верхние 8 бит [0] + [1] малые 56 бит
  uint64_t r1 = ( ( ( ( np  ->  a [ 0 ]  ) >> 56 ) bitor
      ( ( ( np  ->  a [ 1 ]  ) <<  16 ) >> 8 ) ) * ( ( uint64_t  ) m ) ) ;
  // верхние 16 бит [1]
  uint64_t r2 = ( ( ( np  ->  a [ 1 ]  ) >>  48  ) * ( ( uint64_t  ) m ) ) ;
  np->a [ 1 ] = ( r1 >>  8 ) + ( r2 << 48 ) ;
  np->a [ 0 ] = r0 + ( r1 << 56 ) ;
  if ( np ->  a [ 0 ] < r0  ) ++  ( np  ->  a [ 1 ] ) ; }

static  void  string_to_password5_uni ( strcp const string ,
  t_number128 * const restrict password , char (  * letters ) [ ] , uint8_t  letterscount ) {
  char const * restrict stringi = & ( ( * string )  [ 0 ] ) ;
  if  ( ( * stringi ) == '\00' ) {
    number128_set0 ( password  ) ;
    return ; }
  t_number128  pass ;
  number128_set0  ( & pass  ) ;
  t_number128  mult = { { [ 0 ] = 1 , [ 1 ] = 0 } } ;
  do  {
    uint8_t i = letterscount ;
    do {
      -- i ;
      if ( ( * stringi ) == ( * letters ) [ i ] ) goto found ; 
    } while ( i ) ;
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      ( char const ( * ) [ ] ) & u8"неправильная буква в пароле" :
      ( char const ( * ) [ ] ) & "wrong letter in password" ) ;
    longjmp ( ns_shifr  . jump  , 1 ) ;
found : ;
    { t_number128  tmp = mult ;
      number128_mul8  ( & tmp , i + 1 ) ;
      number128_add ( &  pass  , & tmp )  ; }
    number128_mul8  ( & mult , letterscount ) ;
    ++  stringi ;
  } while ( ( * stringi ) not_eq '\00' ) ;
  ( * password  ) = pass ; }
  
static  void  shifr_init ( void  ) {
  { char * j = & ( ns_shifr . letters [ 0 ] ) ;
    for ( uint8_t i = ' ' ; i <= '~' ; ++ i , ++ j ) ( * j ) = i ;  }
  // 0x30 '0' - 0x39 '9' , 0x41 'A' - 0x5a 'Z' , 0x61 'a' - 0x7a 'z'  
  { char * j = & ( ns_shifr . letters2 [ 0 ] ) ;
    for ( uint8_t i = '0' ; i <= '9' ; ++ i , ++ j ) ( * j ) = i ;
    for ( uint8_t i = 'A' ; i <= 'Z' ; ++ i , ++ j ) ( * j ) = i ;
    for ( uint8_t i = 'a' ; i <= 'z' ; ++ i , ++ j ) ( * j ) = i ; } }

# undef isLive5
# define  isLive5 isLive5pub
  
static  void  raspr5_init ( void  ) {
  if ( isLive5  ( & ns_shifr .  raspr5  ) ) return  ;
  uint8_t raspri  = 8 ;
  do {
    uint8_t const raspri4 = raspri * 4 ;
    --  raspri  ;
    // raspri = 7 , 6 , 5 , 4 , 3 , 2 , 1
    // raspri4 = 32 , 28 , 24 , 20 , 16 , 12 , 8
    { uint16_t  j = 0 ;
      type_raspr_xp ( 4 ) ap = malloc  ( sizeof (
          uint8_t [ ns_shifr .  raspr5  . s [ raspri ] ] [ 4 ] ) ) ;
      ns_shifr  . raspr5  . xp [ raspri ] = ap ;
      // ap - указатели на разные массивы
      for ( uint8_t i0 = 0 ; i0 < ( raspri4 - 3 )  ; ++  i0 )
        for ( uint8_t i1 = i0 + 1 ; i1 < (  raspri4 - 2 )  ; ++  i1 )
          for ( uint8_t i2 = i1 + 1 ; i2 < (  raspri4 - 1 ) ; ++  i2 )
            for ( uint8_t i3 = i2 + 1 ; i3 < raspri4 ; ++  i3 ){
              ( * ap ) [ j ] [ 0 ] = i0  ;
              ( * ap ) [ j ] [ 1 ] = i1  ;
              ( * ap ) [ j ] [ 2 ] = i2  ;
              ( * ap ) [ j ] [ 3 ] = i3  ; 
              ++  j ; } }
  } while ( raspri > 1 ) ; 
  isLive5 ( & ns_shifr .  raspr5  ) = true  ; }
  
# undef isLive5
# define  isLive5 isLive5pri

static  void  raspr5_destr ( void  ) {
  if ( not  isLive5 ( & ns_shifr .  raspr5  ) ) return  ;
  uint8_t (**i)[][4]  = & ( ns_shifr  . raspr5  . xp [ 8 ] ) ;
  do {
    --  i ;
    free ( * i ) ;
  } while ( i > & ( ns_shifr  . raspr5  . xp [ 1 ] ) ) ; }
  
static  void  shifr_destr ( void  ) {
  raspr5_destr  ( ) ; }
  
// пароль раскладываем в таблицу шифровки , дешифровки
  // пароль % 0x10 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  // пароль делим на 16, остаются 15! вариантов пароля
  // пароль % 0xf = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
  // секретных кодов для соли+данных 0x1  
// в deshi нужна соль
void  password_load ( uint64_t  const password_const  , arrp const shifrp , 
  arrp const deship ) {
  uint8_t const codefree = 0xff ;
  initarr ( shifrp , codefree , shifr_deshi_size2 )  ;
  initarr ( deship , codefree , shifr_deshi_size2 )  ;
  uint64_t  password = password_const ;
  uint8_t arrind  [ 0x10  ] ;
  { uint8_t * arrj  = & ( arrind  [ 0x10  ] ) ;
    uint8_t j = 0x10  ;
    do  {
      --  arrj  ;
      --  j ;
      ( * arrj )  = j ;
    } while ( arrj  not_eq & ( arrind  [ 0 ] ) ) ;  }
  // 0 .. 15
  uint8_t cindex  = password  bitand  0xf ; //  % 16
  password  >>= 4 ; //  /= 16
  ( * shifrp  ) [ 0 ] = cindex  ;
  ( * deship  ) [ cindex  ] = 0 ;
  uint8_t inde  = 1 ;
  do  {
    memmove ( & ( arrind  [ cindex  ] ) , & ( arrind  [ cindex  + 1 ] ) ,
      0x10  - inde  - cindex  ) ;
    { ldiv_t di = ldiv ( password  , 0x10  - inde ) ;
      cindex  = di . rem ;
      password  = di  . quot  ; 
      ( * shifrp  ) [ inde ] = arrind [ di . rem ] ;
      ( * deship  ) [ arrind [ di . rem ]  ] = inde ; }
    ++  inde  ;
  } while ( inde  < 0x10  ) ; }

// пароль раскладываем в таблицу шифровки , дешифровки
  // пароль % 0x20 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  // пароль делим на 32, остаются 31! вариантов пароля
  // пароль % 0x1f = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
  // секретных кодов для соли+данных 0x1  
void  password_load5 ( t_number128  const * password_constp  , arrp const shifrp , 
  arrp const deship ) {
  uint8_t const codefree = 0xff ;
  initarr ( shifrp , codefree , shifr_deshi_size5 )  ;
  initarr ( deship , codefree , shifr_deshi_size5 )  ;
  t_number128 password = * password_constp ;
  uint16_t  cindex4_32  = number128_div16mod  ( & password  , raspr4_32_size  ) ;
  // 000
  for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
    ( * shifrp  ) [ j ] = ( * ( ns_shifr.raspr5.xp [ 7 ] ) )
       [ cindex4_32 ] [ j ] ;
    ( * deship  ) [ ( * ( ns_shifr.raspr5.xp [ 7 ] ) )
       [ cindex4_32 ] [ j ] ] = j ; }
    // 001-110
      for ( uint8_t arr_ind = 1 ; arr_ind <= 6 ; ++ arr_ind ) {
        uint8_t index = 0 ;
        uint16_t  cindex4_i  = number128_div16mod  ( & password  ,
          ns_shifr.raspr5.s [ 7 - arr_ind ]  ) ;
        { uint8_t old_index = 0xff ;
          for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
            uint8_t new_index = ( * ( ns_shifr.raspr5.xp [ 7 - arr_ind ] ) )
              [ cindex4_i ] [ j ] ;
            { uint8_t passed = old_index + 1 ;
              do {
                if ( (  * deship  ) [ index ] == codefree ) {
                  if ( passed == new_index ) break ;
                  ++ passed  ; }
                ++  index ;
              } while ( true ) ; }
            old_index = new_index ;
            ( * shifrp  ) [ 0x4 * arr_ind + j ] = index ;
            ( * deship  ) [ index ] = ( arr_ind << 2  ) bitor  j ;
            ++  index ; } } } //  for arr_ind
      
      // пароль больше не нужен , беру оставшиеся коды
  // 111
      { uint8_t index3 = 0 ;
        for ( uint8_t  i = 0x1c  ; i <=  0x1f ; ++  i ) {  
          do  {
            if ( (  * deship  ) [ index3 ] == codefree ) break  ;
            ++  index3 ;
          } while ( true  ) ; 
          ( * shifrp  ) [ i ] = index3 ;
          ( * deship  ) [ index3 ] = i ;
          ++  index3 ; } } }  

void datasole ( arrcp const secretdata , arrp const secretdatasole ,
  size_t const data_size ) {
  uint8_t const * restrict  id = &  ( ( * secretdata  ) [ data_size ] ) ;
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ data_size ] ) ;
  int ran = rand ( )  ;
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 101 =>
    //   101_00 или 101_01 или 101_10 или 101_11
    // в таблице всё рядом, 4 варианта равномерно распределены
    ( * ids ) = ( ( * id  ) <<  2 ) bitor ( ran bitand  0x3 ) ;
    ran >>= 2 ;
  } while ( id not_eq & ( ( * secretdata  ) [ 0 ] ) ) ; }

void  data_xor  ( uint8_t * const restrict  old_last_sole ,
  arrp  const secretdatasole  , size_t  const data_size ) {
  uint8_t * restrict  ids = & ( ( * secretdatasole  ) [ 0 ] ) ;
  do {
    // главное данные , хвост - соль : 01 =>
    //   01_00 или 01_01 или 01_10 или 01_11
    // в таблице всё рядом, 4 варианта равномерно распределены
    // данные сыпью предыдущей солью
    ( * ids ) xor_eq  ( ( * old_last_sole ) << 2  ) ;
    // берю свежую соль
    ( * old_last_sole ) = ( * ids ) bitand  0x3 ;
    ++  ids ;
  } while ( ids not_eq & ( ( * secretdatasole ) [ data_size ] ) ) ; }

static  void  char_to_hex ( char  buf , char ( * const buf2 ) [ 2 ] ) {
  unsigned  char c = buf bitand 0xf ;
  if ( c >= 0 and c <= 9 ) (*buf2)[0] = '0' + c ;
  else  (*buf2)[0] = 'a' + (c - 10) ;
  c = (buf >> 4) bitand 0xf ;
  if ( c >= 0 and c <= 9 ) (*buf2)[1] = '0' + c ;
  else  (*buf2)[1] = 'a' + (c - 10) ; }

static  inline  char  bits5_to_letter ( uint8_t const bits5 ) {
  if  ( bits5 < 0x10  ) return  'a' + bits5 ;
  return  'A' + ( bits5 - 0x10  ) ; }

static  inline  uint8_t letter_to_bits5 ( char  const letter  ) {
  if  ( ( ( uint8_t ) letter )  >=  ( ( uint8_t ) 'a' ) ) return  letter  - 'a' ;
  return  0x10  + ( letter  - 'A' ) ; }

static  void  hex_to_char ( char const ( * restrict buf2 ) [ 2 ] ,
  char * const restrict buf ) {
  if  ((*buf2)[0] >= '0' and (*buf2)[0] <= '9') (* buf) = (*buf2)[0] - '0';
  else
    if((*buf2)[0] >= 'a' and (*buf2)[0] <= 'f') (* buf) = 10 + ((*buf2)[0] - 'a');
  else  {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      (char const (*)[]) & u8"плохая hex буква" :
      (char const (*)[])& "bad hex letter" ) ;
    longjmp(ns_shifr  . jump,1); }
  if  ((*buf2)[1] >= '0' and (*buf2)[1] <= '9')
    (* buf) or_eq (((*buf2)[1] - '0')<<4);
  else
    if((*buf2)[1] >= 'a' and (*buf2)[1] <= 'f')
      (* buf) or_eq ((10 + ((*buf2)[1] - 'a'))<<4);
  else  {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      (char const (*)[]) & u8"плохая hex буква" :
      (char const (*)[]) & "bad hex letter" ) ;
    longjmp(ns_shifr  . jump,1); } }
    
// Отключить эхо-вывод и буферизацию ввода
static  void set_keypress (void) {
  if  ( tcgetattr ( 0 , & ns_shifr  . stored_termios  ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifr . localerus ?
      u8"ошибка чтения tcgetattr : %s\n" :
      "error read tcgetattr : %s\n" ) ,se ) ;
    ns_shifr  . string_exception  = (char const (*)[])se ;
    longjmp(ns_shifr  . jump,1); }

  struct termios new_termios = ns_shifr . stored_termios  ;
  new_termios.c_lflag &= ~(ECHO bitor ICANON);
  new_termios.c_cc[VMIN] = 1;  
  new_termios.c_cc[VTIME] = 0; 
 
  if(tcsetattr(0, TCSANOW, & new_termios)){
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifr . localerus ?
      u8"ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifr  . string_exception  = (char const (*)[])se ;
    longjmp(ns_shifr  . jump,1); } }
 
// Восстановление дефолтного состояния
static  void reset_keypress (void) {
  if  ( tcsetattr ( 0 , TCSANOW , & ns_shifr . stored_termios ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifr . localerus ?
      u8"ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifr  . string_exception  = (char const (*)[]) se ;
    longjmp(ns_shifr  . jump,1); } }  
  
typedef struct  s_streambuf  {
  // file
  FILE  * oRmq  ;
  // buf
  uint8_t FmoX ;
  // bufbitsize
  uint8_t XUvM  ;
  // bytecount
  int D6h7 ;
} t_streambuf ;
  
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

static  inline  int streambuf_ByteCount  ( t_streambuf const * const restrict me ) {
  return  streambuf_bytecount ( me  ) ; }

static  inline  uint8_t streambuf_BufBitSize  (
  t_streambuf const * const restrict me ) {
  return  streambuf_bufbitsize ( me  ) ; }

static  inline  uint8_t streambuf_Buf (
  t_streambuf const * const restrict me ) {
  return  streambuf_buf ( me  ) ; }

// читаю 5 бит
bool  isEOFstreambuf_read5bits ( t_streambuf * const restrict me  ,
  uint8_t * const encrypteddata , bool const  flagtext ) {
  if  ( ( not flagtext ) and streambuf_bufbitsize  ( me  ) >= 5 ) {
    streambuf_bufbitsize  ( me  ) -=  5 ;
    ( * encrypteddata ) = streambuf_buf ( me  ) bitand 0x1f ;
    streambuf_buf ( me  ) >>= 5 ;
    return  false ; }
  uint8_t buf ;
  { size_t  const nreads  = fread ( & buf , 1 , 1 , streambuf_file  ( me  ) ) ;
    if ( nreads ==  0 ) {
      if  ( feof  ( streambuf_file  ( me  ) ) ) return  true  ;
      if  ( ferror  ( streambuf_file  ( me  ) ) ) {
        clearerr ( streambuf_file  ( me  ) ) ;
        ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
          (char const (*)[]) &
          u8"isEOFstreambuf_read5bits: ошибка чтения пяти бит" :
          (char const (*)[]) & "isEOFstreambuf_read5bits: five bits read error" ) ;
        longjmp(ns_shifr  . jump,1); } } } // nreads

  if  ( flagtext  ) {
    // читаем одну букву 'A'-'P'|'a'-'p' -> декодируем в пять бит
    // если это НЕ большая и НЕ маленькая
    while ( ( buf < 'A' or buf > 'P') and ( buf < 'a' or buf > 'p') ) {
      { size_t  const nreads  = fread ( & buf , 1 , 1 , streambuf_file  ( me  ) ) ;
        if ( nreads ==  0 ) {
          if  ( feof  ( streambuf_file  ( me  ) ) ) return  true  ;
          if  ( ferror  ( streambuf_file  ( me  ) ) ) {
            clearerr ( streambuf_file  ( me  ) ) ;
            ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
              (char const (*)[]) &
              u8"isEOFstreambuf_read5bits: ошибка чтения пяти бит из текста" :
              (char const (*)[]) &
              "isEOFstreambuf_read5bits: five bits read error from text" ) ;
            longjmp(ns_shifr  . jump,1); } } } // nreads
          } //  while not digit and not letter
    ( * encrypteddata ) = letter_to_bits5 ( buf ) ; }
  else  {
    ( * encrypteddata ) = ( streambuf_buf ( me  ) bitor 
      ( buf <<  streambuf_bufbitsize  ( me  ) ) ) bitand  0x1f  ;
    streambuf_buf ( me  ) = buf >>  ( 5 - streambuf_bufbitsize  ( me  ) ) ;
    streambuf_bufbitsize  ( me  ) +=  3 ; } // + 8 - 5
  return  false ; }
  
// пишу по пять бит
// secretdatasolesize количество пяти-битных отделов (2 или 3)
// encrypteddata массив пяти-битных чисел
void  streambuf_write ( t_streambuf * const restrict me  ,
  uint8_t const (  * encrypteddata ) [ 3 ] , uint8_t secretdatasolesize ,
  bool const  flagtext ) {
  for ( uint8_t i = 0 ; i < secretdatasolesize ; ++  i ) {

    if  ( flagtext  ) {
        char  buf2  = bits5_to_letter ( ( * encrypteddata ) [ i ] ) ;
        size_t  writen_count  ;
        writen_count  = fwrite  ( & buf2  , 1 , 1 , streambuf_file  ( me  ) ) ;
        if  ( writen_count  ==  0 ) {
          clearerr  ( streambuf_file  ( me  ) ) ; 
          ns_shifr  . string_exception  = ( ns_shifr  . localerus ? 
            ( char  const ( * ) [ ] ) & u8"streambuf_write: ошибка записи байта"  :
            ( char  const ( * ) [ ] ) & "streambuf_write: byte write error" ) ;
          longjmp ( ns_shifr  . jump  , 1 ) ; }
        ++  streambuf_bytecount ( me  ) ;
        if  ( streambuf_bytecount ( me  ) >=  36  ) {
          streambuf_bytecount ( me  ) = 0 ;
          buf2  = '\n'  ;
          writen_count  = fwrite  ( & buf2  , 1 , 1 ,
            streambuf_file  ( me  ) ) ; }
        
         } else {

    if  ( streambuf_bufbitsize  ( me  ) < 3 ) {
      streambuf_buf ( me  ) or_eq ( ( ( * encrypteddata ) [ i ] ) <<
        streambuf_bufbitsize  ( me  ) ) ;
      streambuf_bufbitsize  ( me  ) +=  5 ; }
    else  {
      uint8_t const to_write  = ( ( ( * encrypteddata ) [ i ] ) <<
        streambuf_bufbitsize  ( me  ) ) bitor streambuf_buf ( me  ) ;
        size_t  writen_count  ;
        writen_count = fwrite ( & to_write , 1 , 1 ,
          streambuf_file  ( me  ) ) ;
      if ( writen_count < 1 ) {
        clearerr ( streambuf_file  ( me  ) ) ; 
        ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
          (char const (*)[]) & u8"streambuf_write: ошибка записи байта" :
          (char const (*)[]) & "streambuf_write: byte write error" ) ;
        longjmp(ns_shifr  . jump,1); }
      
        // + 5 - 8
        streambuf_bufbitsize  ( me  ) -= 3 ;
        streambuf_buf ( me  ) = ( ( * encrypteddata ) [ i ] ) >>
          ( 5 - streambuf_bufbitsize  ( me  ) ) ;  } }}}
        
void  streambuf_writeflushzero ( t_streambuf * const restrict me ,
  bool const  flagtext ) {
  if  ( streambuf_bufbitsize  ( me  ) ) {
    size_t  writen_count  ;
    
      writen_count = fwrite ( & streambuf_buf ( me  ) , 1 , 1 ,
        streambuf_file  ( me  ) ) ;
    if ( writen_count < 1 ) {
      clearerr ( streambuf_file  ( me  ) ) ; 
      ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
        (char const (*)[]) & u8"streambuf_writeflushzero: ошибка записи байта" :
        (char const (*)[]) & "streambuf_writeflushzero: byte write error" ) ;
      longjmp(ns_shifr  . jump,1); }
    streambuf_bufbitsize  ( me  ) = 0 ; }
  if ( flagtext and streambuf_bytecount ( me  ) )  {
    streambuf_bytecount ( me  ) = 0 ;
    char  buf2 = '\n' ;
    size_t  const writen_count = fwrite ( & buf2 , 1 , 1 , 
      streambuf_file  ( me  ) ) ;
    if ( writen_count < 1 ) {
      clearerr ( streambuf_file  ( me  ) ) ; 
      ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
        (char const (*)[]) & u8"streambuf_writeflushzero: ошибка записи байта" :
        (char const (*)[]) & "streambuf_writeflushzero: byte write error" ) ;
      longjmp(ns_shifr  . jump,1); } } }
  
// версия 5 пишу три бита для расшифровки
void  streambuf_write3bits ( t_streambuf * const restrict me  ,
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
          (char const (*)[]) & u8"streambuf_write3bits: ошибка записи байта" :
          (char const (*)[]) & "streambuf_write3bits: byte write error" ) ;
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

int main  ( int  argc , char * * argv  )  {
  char const * const locale = setlocale ( LC_ALL  , ""  ) ;
  ns_shifr . localerus = ( strcmp  ( locale  , "ru_RU.UTF-8" ) ==  0 ) ;
  int exc = setjmp  ( ns_shifr  . jump  ) ;
  if ( exc ) {
    fprintf ( stderr  , ( ns_shifr . localerus ? u8"Исключение : %s\n" :
      "Exception : %s\n" ) , & ( ( *  ns_shifr  . string_exception ) [ 0 ] ) ) ;
    shifr_destr ( ) ;
    return  1 ; }
  bool  flagenc = false ;
  bool  flagdec = false ;
  bool  flagpasswd  = false ;
  bool  flaggenpasswd  = false ;
  bool  flagreadpasswd  = false ;
  bool  flagreadinput = false ;
  bool  flagreadoutput = false ;
  strcp inputfilename = & u8""  ;
  strcp outputfilename  = & u8""  ;
  bool  flaginputfromfile = false ;
  bool  flagoutputtofile  = false ;
  bool  flagclosefilefrom = false ;
  bool  flagclosefileto = false ;
  bool  flagtext  = false ;
  int password_alphabet = 62 ;
  shifr_init  ( ) ;
  if  ( argc  <=  1  ) {
    puts ( ns_shifr . localerus ?
      u8"Шифр4 ©2019 Глебов А.Н.\nСимметричное поточное шифрование с 'солью'.\n'Соль' генерируется постоянно, что даёт хорошую стойкость.\nРазмер данных увеличивается в два раза.\nНет диагностики неправильного пароля.\nСинтаксис : shifr4 [параметры]" :
      "Shifr4 ©2019 Glebe A.N.\nSymmetric stream encryption with 'salt'.\n'Salt' is constantly generated, which gives good durability.\nData size doubles.\nThere is no diagnosis of the wrong password.\nSyntax : shifr4 [options]" ) ;
    puts  ( ns_shifr . localerus ? u8"Параметры :" : "Options :"  ) ;
    puts  (ns_shifr . localerus ?
      u8"  --ген-пар или\n  --gen-pas\tгенерировать пароль" :
      "  --gen-pas\tpassword generate" );
    puts  (ns_shifr . localerus ?
      u8"  --зашифр или\n  --encrypt\tзашифровать\t(по-умолчанию)" :
      "  --encrypt\t(by default)" );
    puts  (ns_shifr . localerus ? u8"  --расшифр или\n  --decrypt\tрасшифровать" :
      "  --decrypt" );
    puts  (ns_shifr . localerus ?
      u8"  --пароль или\n  --pass 'строка_пароля'\tиспользовать данный пароль" :
      "  --pass 'password_string'\tuse this password" );
/* ! --пар-путь --psw-path */
    puts  (ns_shifr . localerus ?
      u8"  --вход или\n  --input 'имя_файла'\tчитать из файла (без данной опции читаются данные со стандартного входа)" :
      "  --input 'file_name'\tread from file (without this option data reads from standard input)");
    puts  (ns_shifr . localerus ? 
      u8"  --выход или\n  --output 'имя_файла'\tзаписывать в файл (без данной опции записываются данные в стандартный выход)" :
      "  --output 'file_name'\twrite to file (without this option data writes to standard output)"    );
    puts  (ns_shifr . localerus ? 
      u8"  --текст или\n  --text\tшифрованный файл записан текстом ascii" :
      "  --text\tencrypted file written in ascii text"    );
    puts  ( ns_shifr . localerus ? 
      u8"  --4\tиспользовать четырёх битное шифрование, ключ = 45 бит ( семь/восемь букв ). Размер шифрованного файла в два раза больше исходного. ( по-умолчанию )" :
      "  --4\tusing four bit encryption, key = 45 bits ( seven/eight letters ). The encrypted file is twice the size of the original. ( by default )" ) ;
    puts  ( ns_shifr . localerus ? 
      u8"  --5\tиспользовать пяти битное шифрование, ключ = 81 бит ( тринадцать/четырнадцать букв ). Размер шифрованного файла на 67% больше исходного. (экспериментальная версия)" :
      "  --5\tusing five bit encryption, key = 81 bits ( thirteen/fourteen letters ). The encrypted file is 67% larger than the original. (experimental version)" ) ;
    puts  ( ns_shifr . localerus ?
      u8"--6\tиспользовать шести битное шифрование, ключ = 296 бит ( 46 - 50 букв )." :
      "--6\tusing six bit encryption, key = 296 bits ( 46 - 50 letters ).") ;
    fputs  ( ns_shifr . localerus ?  
      u8"Буквы в пароле (алфавит):\n  --а95 или\n  --a95\t\'" :
      "Letters in password (alphabet):\n  --a95\t\'" , stdout ) ;
    for ( char const * cj = & ( ns_shifr  . letters [ 0 ] ) ;
      cj not_eq ( & ( ns_shifr  . letters [ letters_count ] ) ) ; ++ cj )
      fputc ( * cj  , stdout  ) ;
    fputs ( ( ns_shifr . localerus ? u8"\'\n  --а62 или\n  --a62\t\'" :
      "\'\n  --a62\t\'" ) , stdout  ) ;
    for ( char const * cj = & ( ns_shifr  . letters2 [ 0 ] ) ;
      cj not_eq ( & ( ns_shifr  . letters2 [ letters_count2 ] ) ) ; ++ cj )
      fputc ( * cj  , stdout  ) ;
    fputs ( ( ns_shifr . localerus ? u8"\'\t(по умолчанию)\n" :
      "\'\t(by default)\n"  ) , stdout  ) ;
    puts  ( ns_shifr  . localerus ? u8"Пример использования :"  :
      "Usage example"  ) ;
    puts  ( ns_shifr  . localerus ? u8"  > ./shifr4 --ген-пар"  :
      "  > ./shifr4 --gen-pas"  ) ;
    puts("  ueKZ9sH4");
    puts  ( ns_shifr  . localerus ?
      u8"  > ./shifr4 --пароль 'ueKZ9sH4' > test.e --текст"  :
      "  > ./shifr4 --pass 'ueKZ9sH4' > test.e --text"  ) ;
    puts( ns_shifr  . localerus ? u8"  2+2 (Нажимаем Enter,Ctrl+D)" :
      "  2+2 (Press Enter,Ctrl+D)" ) ;
    puts("  > cat test.e");
    puts("  c9f29d22e4ef08f2");
    puts( ns_shifr  . localerus ?
      u8"  > ./shifr4 --пароль 'ueKZ9sH4' < test.e --текст --расшифр" :
      "  > ./shifr4 --pass 'ueKZ9sH4' < test.e --text --decrypt" ) ;
    puts("  2+2");
    shifr_destr ( ) ;
    return 0 ; }
# if  RAND_MAX  !=  0x7fffffff
# error RAND_MAX  !=  0x7fffffff
# endif
  // 31 бит
  srand ( time  ( 0 ) ) ;
  for ( int argj = 1 ; argv [ argj ] ; ++ argj ) {
    if  ( flagreadpasswd  ) {
      if  ( flagpasswd  ) {
        ns_shifr  . string_exception  = ( ns_shifr . localerus ?
          (char const (*)[]) & u8"пароль уже задан" :
          (char const (*)[]) & "password already set" );
        longjmp(ns_shifr  . jump,1); }
      if ( ns_shifr . use_version == 4 ) {
        if ( password_alphabet == 95 )
          string_to_password_uni ( (  char  ( * ) [ ] ) ( argv  [ argj  ] ) ,
            & ns_shifr . raspr4  . password_const , & ns_shifr . letters ,
            letters_count ) ; 
        else
          string_to_password_uni ( (  char  ( * ) [ ] ) ( argv  [ argj  ] ) ,
            & ns_shifr . raspr4  . password_const , & ns_shifr . letters2 ,
            letters_count2 ) ;
# ifdef SHIFR_DEBUG
      printf  ( (ns_shifr . localerus ? u8"из строки во внутренний пароль = %lx\n" :
        "from string to internal password = %lx\n" ) ,
        ns_shifr . raspr4  . password_const ) ;
# endif                           
        }
      else {
        if ( password_alphabet == 95 )
          string_to_password5_uni ( (char(*)[])(argv[argj]) ,
            & ns_shifr . raspr5  . password_const , & ns_shifr . letters ,
            letters_count ) ;
        else
          string_to_password5_uni ( (char(*)[])(argv[argj]) ,
            & ns_shifr . raspr5  . password_const , & ns_shifr . letters2 ,
            letters_count2 ) ; 
# ifdef SHIFR_DEBUG                           
        { t_number128 password5 ;
          if ( password_alphabet == 95 )
            string_to_password5_uni ( (char(*)[])(argv[argj]) , & password5 ,
              & ns_shifr . letters , letters_count ) ; 
          else
            string_to_password5_uni ( (char(*)[])(argv[argj]) , & password5 ,
              & ns_shifr . letters2 , letters_count2 ) ; 

          printf  ( ( ns_shifr . localerus ?
            u8"из строки во внутренний пароль = [ %lx , %lx ]\n"  :
            "from string to internal password = [ %lx , %lx ]\n"  ) ,
          password5 . a [ 1 ] , password5 . a [ 0 ] ) ; }
# endif            
      }
      char  password_letters [ 20 ] ;
      if ( ns_shifr . use_version == 4 )
        if ( password_alphabet == 95 )
          password_to_string_uni ( ns_shifr . raspr4  . password_const ,
            & password_letters , & ns_shifr . letters , letters_count ) ;
        else
          password_to_string_uni ( ns_shifr . raspr4  . password_const ,
            & password_letters , & ns_shifr . letters2 , letters_count2 ) ;
      else  {
        if ( password_alphabet == 95 )
          password_to_string5_uni ( & ns_shifr . raspr5  . password_const ,
            & password_letters , & ns_shifr . letters , letters_count ) ;
        else
          password_to_string5_uni ( & ns_shifr . raspr5  . password_const ,
            & password_letters , & ns_shifr . letters2 , letters_count2 ) ; }
        if  ( strcmp ( password_letters , argv  [ argj  ] ) )  
          fprintf  ( stderr , ns_shifr . localerus ?
            u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
            "Warning! Password \'%s\' is very large. Same as \'%s\'\n"
            , argv  [ argj  ] , & ( password_letters  [ 0 ] ) ) ;         
        flagpasswd  = true  ;
        flagreadpasswd = false  ; }
      else
        if ( flagreadinput ) {
          inputfilename = (char const (*)[])(argv[argj]) ;
          flaginputfromfile = true ;
          flagreadinput = false ; }
        else
         if ( flagreadoutput ) {
          outputfilename = (char const (*)[])(argv[argj]) ;
          flagoutputtofile = true ;
          flagreadoutput = false ; }
        else 
      if (( strcmp ( argv[argj] , u8"--ген-пар" ) ==  0 ) or
        (strcmp ( argv[argj] , "--gen-pas" ) ==  0)) 
        flaggenpasswd = true  ; 
      else  {
        if (( strcmp ( argv[argj] , u8"--зашифр" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--encrypt" ) ==  0 ) ) {
          flagenc = true ;
          flagdec = false ; }
        else
        if (( strcmp ( argv[argj] , u8"--расшифр" ) ==  0 )or
          ( strcmp ( argv[argj] , "--decrypt" ) ==  0 )) { 
          flagdec = true ;
          flagenc = false ; }
        else
        if (( strcmp ( argv[argj] , u8"--пароль" ) ==  0 )or
          ( strcmp ( argv[argj] , "--pass" ) ==  0 )) { 
          flagreadpasswd  = true  ; }
/* ! --пар-путь --psw-path */
        else
        if (( strcmp ( argv[argj] , u8"--вход" ) ==  0 )or
          ( strcmp ( argv[argj] , "--input" ) ==  0 )) { 
          flagreadinput  = true  ; }
        else
        if (( strcmp ( argv[argj] , u8"--выход" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--output" ) ==  0 )){ 
          flagreadoutput  = true  ; }  
        else
        if (( strcmp ( argv[argj] , u8"--текст" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--text" ) ==  0 )){ 
          flagtext = true  ; }
        else
        if ( strcmp ( argv[argj] , u8"--4" ) ==  0 ){ 
          ns_shifr . use_version = 4 ; }
        else
        if ( strcmp ( argv[argj] , u8"--5" ) ==  0 ){ 
          raspr5_init ( ) ;
          ns_shifr . use_version = 5 ; }
        else
        if ( strcmp ( argv  [ argj  ] , u8"--6" ) ==  0 ) { 
          raspr5_init ( ) ;
          ns_shifr . use_version = 6 ; }
        else
        if (( strcmp ( argv[argj] , u8"--а95" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--a95" ) ==  0 )) { 
          password_alphabet = 95 ; }
        else
        if (( strcmp ( argv[argj] , u8"--а62" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--a62" ) ==  0 )) { 
          password_alphabet = 62 ; }
        else {
          fprintf ( stderr , ( ns_shifr . localerus ?
            u8"неопознанная опция : \'%s\'\n" :
            "unrecognized option : \'%s\'\n" ) , argv [ argj ] ) ;
          ns_shifr  . string_exception  = ( ns_shifr . localerus ?
            (char const (*)[])& u8"неопознанная опция" :
            (char const (*)[])& "unrecognized option" ) ;
          longjmp(ns_shifr  . jump,1); } } }
  if ( flaggenpasswd ) {
    switch  ( ns_shifr . use_version  ) {
    case  4 :
      { int r1 , r0 ;
      // 22 из 31 , 23 из 31
      // максимальный рандом < 2494190 * ( 2 ^ 23 ) + 7700480 == 20922789888000
      // цикл для равномерного рандома
# define  shifrrandmax1  (2494190)
# define  shifrrandmax0  (7700480)
      do {
        do {
          r1 = rand  ( ) >> 9 ;
        } while ( r1 >  shifrrandmax1  ) ;
        r0 = rand  ( ) >> 8 ;
      } while ( ( r1 ==  shifrrandmax1  ) and ( r0 >= shifrrandmax0 ) ) ;
      ns_shifr . raspr4  . password_const = ( ( ( uint64_t  ) r1  ) <<  23 ) bitor
        ( ( uint64_t  ) r0 ) ;
# undef shifrrandmax0
# undef shifrrandmax1
      break ; }
    case  5 :
      { t_number96 ro0 ;
      t_number96 ro ;      
/*
 сверху 1 бит всегда ноль,
 снизу 4 бита у всех рандомов округляю
     [1 17 10 4 ]      [1 22 5 4 ]      [1 27 4] 
      |      |         |        |       |   
  [ 17 ]      [ 10 22 ]         [ 5 27]
  в сумме 17+32+32=81 бит   

!!

микросекунды , два рандома 
19 + 31 + 31 = 81 бит

[1 17 2]   [1  30  1]     [1   31]
   |   |       |     |        |
[17]   [2    30]      [1    31]

#include <sys/time.h>

**
 * Returns the current time in microseconds.
 *
long getMicrotime(){
	struct timeval currentTime;
	gettimeofday(&currentTime, NULL);
	return currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
}

Циклом не делать, будет неравномерность. Берём 19 бит. 
Пихаем в
 ro.a  [ 2 ] = currentTime.tv_usec bitand ((1UL<<19)-1);

 */      
randtry :
      ro0 = (t_number96){{ rand  ( ) , rand  ( ) , rand  ( ) }} ;
      ro.a  [ 0 ] = ro0.a [ 0 ] >> 4 ;
      ro.a  [ 0 ] or_eq ( ( ro0.a [ 1 ] >> 4 ) << 27 ) ;
      ro.a  [ 1 ] = ro0.a [ 1 ] >>  9 ;
      ro.a  [ 1 ] or_eq ( ( ro0.a [ 2 ] >> 4 ) << 22 ) ;
      ro.a  [ 2 ] = ro0.a [ 2 ] >>  14 ;
# define  randompassmax2 (UINT32_C(129587))
# define  randompassmax1 (UINT32_C(839460196))
# define  randompassmax0 (UINT32_C(130987392))
      if  ( ro.a  [ 2 ] < randompassmax2 )  goto  randok ;
      if  ( ro.a  [ 2 ] > randompassmax2 )  goto  randtry ; 
      if  ( ro.a  [ 1 ] < randompassmax1 )  goto  randok ;
      if  ( ro.a  [ 1 ] > randompassmax1 )  goto  randtry ;
      if  ( ro.a  [ 0 ] < randompassmax0 )  goto  randok ;
      if  ( ro.a  [ 0 ] >=  randompassmax0 )  goto  randtry ; 
# undef randompassmax0
# undef randompassmax1
# undef randompassmax2
randok :
  ns_shifr . raspr5  . password_const = (  t_number128 ) { {
    [ 1 ] = ro  . a [ 2 ] , [ 0 ] = ( ( ( uint64_t  ) ( ro  . a [ 1 ] ) ) <<  32  )
    bitor ( ( uint64_t  ) ( ro  . a [ 0 ] ) ) } } ;     
      break ; }
    case 6 :
      { int const rmax  [ 10 ] = { 0 , 0 , 371982424 , 465456948 , 36645132 ,
          851424078 , 78362151 , 525642490 , 110135612 , 535066862 } ;
        int r [ 10  ] ;
        int * ri  ;
rand6try :
        ri  = & ( r [ 10  ] ) ;
        do {
          -- ri ;
          ( * ri ) = rand ( ) >> 2 ;
        } while ( ri not_eq ( & ( r [ 6 ] ) ) ) ;
        do {
          -- ri ;
          ( * ri ) = rand ( ) >> 1 ;
        } while ( ri not_eq ( & ( r [ 0 ] ) ) ) ;
        ri =  & ( r [ 10  ] ) ;
        { int const * rmaxi  = & ( rmax [ 10  ] ) ;
          do {
            --  ri  ;
            --  rmaxi ;
            if ( ( * ri ) < ( * rmaxi ) ) goto rand6ok ;
            if ( ( * ri ) > ( * rmaxi ) ) {
printf  ( u8"большое %x " , * ri  ) ;
              goto rand6try ; }
          } while ( ri not_eq ( & ( r [ 2 ] ) ) ) ; }
        goto  rand6try ;
rand6ok :
# ifdef SHIFR_DEBUG
      fputs ( ns_shifr . localerus ? u8"внутренний пароль = [ "  :
        "inner password = [ " , stdout ) ;
      for ( int const * i = & ( r [ 10 ] ) ; i not_eq & ( r [ 0 ] ) ;  ) {
        --  i ;
        printf ( "%x , " , * i ) ;  }
      puts  ( "]" ) ;
# endif
      //ns_shifr . raspr6  . password_const = r ;
      break ; }
    default :
      fprintf ( stderr , ( ns_shifr . localerus ?
        u8"неопознанная версия : \'%d\'\n" :
        "unrecognized version : \'%d\'\n" ) , ns_shifr . use_version ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( char const (  * ) [ ] ) & u8"неопознанная версия" :
        ( char const (  * ) [ ] ) & "unrecognized version" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; }
  flagpasswd  = true  ;
# ifdef SHIFR_DEBUG    
  switch ( ns_shifr . use_version ) {
  case  4 :
    printf  ( ( ns_shifr . localerus ? u8"внутренний пароль = %lx\n" :
      "internal password = %lx\n") , ns_shifr . raspr4  . password_const  ) ;
    break ;
  case  5 :
    printf  ( ( ns_shifr . localerus ? u8"внутренний пароль = [ %lx , %lx ]\n"  :
      "inner password = [ %lx , %lx ]\n"  ) ,
      ns_shifr . raspr5  . password_const . a [ 1 ] ,
      ns_shifr . raspr5  . password_const . a [ 0 ] ) ;
    break ;
  case  6 :
/*    fputs ( ns_shifr . localerus ? u8"внутренний пароль = [ "  :
      "inner password = [ " ) ;
    for ( int const * i = & ( ns_shifr . raspr6  . password_const . a [ 0 ] ) ;
      i not_eq & ( ns_shifr . raspr6  . password_const . a [ 10 ] ) ;
      ++  i ) print ( "%x , " , * i ) ;*/
    break ;
  default :
    fprintf ( stderr , ( ns_shifr . localerus ?
      u8"неопознанная версия : \'%d\'\n" :
      "unrecognized version : \'%d\'\n" ) , ns_shifr . use_version ) ;
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      ( char const (  * ) [ ] ) & u8"неопознанная версия" :
      ( char const (  * ) [ ] ) & "unrecognized version" ) ;
    longjmp ( ns_shifr  . jump  , 1 ) ; }
# endif
    char  password_letters [ 20 ] ;
    char  password_letters2 [ 20 ] ;
    
    if ( ns_shifr . use_version == 4 ) {
      password_to_string_uni ( ns_shifr . raspr4  . password_const ,
        & password_letters , & ns_shifr . letters , letters_count ) ;
      password_to_string_uni ( ns_shifr . raspr4  . password_const ,
        & password_letters2 , & ns_shifr . letters2 , letters_count2 ) ; }
    else {
      password_to_string5_uni ( & ns_shifr . raspr5  . password_const ,
        & password_letters , & ns_shifr . letters , letters_count ) ;
      password_to_string5_uni ( & ns_shifr . raspr5  . password_const ,
        & password_letters2 , & ns_shifr . letters2 , letters_count2 ) ; }
# ifdef SHIFR_DEBUG      
  printf  ( ( ns_shifr . localerus ? u8"--a95\tбуквами между кавычек = \'%s\'\n" : 
    "--a95\tby letters between quotes = \'%s\'\n"  ) ,
    & ( password_letters  [ 0 ] ) ) ;
  printf  ( ( ns_shifr . localerus ?
    u8"--a62\tбуквами между кавычек = \'%s\' (по-умолчанию)\n" : 
    "--a62\tby letters between quotes = \'%s\' (by default)\n"  ) ,
    & ( password_letters2  [ 0 ] ) ) ;
    if ( ns_shifr . use_version == 4 ) {
      uint64_t password2 ;
      string_to_password_uni ( & password_letters , & password2  ,
        & ns_shifr . letters , letters_count ) ; 
      printf  ( ( ns_shifr . localerus ?
        u8"из строки95 во внутренний пароль = %lx\n" :
        "from string95 to internal password = %lx\n" ) , password2 ) ;
      string_to_password_uni ( & password_letters2 , & password2  ,
        & ns_shifr . letters2 , letters_count2 ) ; 
      printf  ( ( ns_shifr . localerus ?
        u8"из строки62 во внутренний пароль = %lx\n" :
        "from string62 to internal password = %lx\n" ) , password2 ) ; }
    else  {
      t_number128 password5 ;
        string_to_password5_uni ( & password_letters , & password5 , & ns_shifr . letters , letters_count ) ; 
      printf  ( ( ns_shifr . localerus ?
          u8"из строки95 во внутренний пароль = [ %lx , %lx ]\n"  :
          "from string95 to internal password = [ %lx , %lx ]\n" ) ,
        password5 . a [ 1 ] , 
        password5 . a [ 0 ] ) ;
        string_to_password5_uni ( & password_letters2 , & password5 , & ns_shifr . letters2 , letters_count2 ) ; 
      printf  ( ( ns_shifr . localerus ?
          u8"из строки62 во внутренний пароль = [ %lx , %lx ]\n"  :
          "from string62 to internal password = [ %lx , %lx ]\n" ) ,
        password5 . a [ 1 ] , 
        password5 . a [ 0 ] ) ;   }
# else
  if ( password_alphabet == 95 ) puts  ( & ( password_letters  [ 0 ] ) ) ;
  else puts  ( & ( password_letters2  [ 0 ] ) ) ;
# endif    
    if ( not flagoutputtofile ) return  0 ;  }
  if  ( flagenc and flagdec ) {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      (char const (*)[])& u8"так зашифровывать или расшифровывать ?" :
      (char const (*)[])& u8"so encrypt or decrypt ?" ) ;
    longjmp(ns_shifr  . jump,1); }
  //  по-умолчанию шифруем
  if ( not flagdec  ) flagenc = true  ;
  if ( not flagpasswd )    {

// ! искать в ~/.shifr4/default ?

    char p [ 26 ] ;
    fputs ( ( ns_shifr . localerus ? u8"введите пароль = " :
      "enter the password = " ) , stdout  ) ;
    set_keypress  ( ) ;
    char ( * res ) [ 26 ] = ( char ( * ) [ 26 ] )
      fgets ( & ( p [ 0 ] ) , 26 , stdin ) ;
    reset_keypress ( ) ;
    char * j = &((*res)[0]) ;
    while ( ( ( * j ) not_eq '\n' ) and ( ( * j ) not_eq '\00' ) and
      ( j < ( & ( * res ) [ 26 ] ) ) ) ++ j ;
    if ( j < ( & ( ( * res ) [ 26 ] ) ) ) ( * j ) = '\00' ;
    else  {
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"в пароле нет конца строки" :
        (char const (*)[]) & "there is no end of line in the password" ) ;
      longjmp(ns_shifr  . jump,1); }
    if ( ns_shifr . use_version == 4 )
      if ( password_alphabet == 95 )
        string_to_password_uni ( res , & ns_shifr . raspr4  . password_const ,
          & ns_shifr . letters ,  letters_count ) ;
      else
        string_to_password_uni ( res , & ns_shifr . raspr4  . password_const ,
          & ns_shifr . letters2 , letters_count2 ) ;
    else {
      if ( password_alphabet == 95 )
        string_to_password5_uni ( res , & ns_shifr . raspr5  . password_const ,
          & ns_shifr . letters ,  letters_count ) ;
      else
        string_to_password5_uni ( res , & ns_shifr . raspr5  . password_const ,
          & ns_shifr . letters2 , letters_count2 ) ; }
    char  password_letters [ 20 ] ;
    if ( ns_shifr . use_version == 4 ) {
      if ( password_alphabet == 95 )
        password_to_string_uni ( ns_shifr . raspr4  . password_const ,
          & password_letters , & ns_shifr . letters , letters_count ) ;
      else
        password_to_string_uni ( ns_shifr . raspr4  . password_const ,
          & password_letters , & ns_shifr . letters2 , letters_count2 ) ; }
      else  {
        if ( password_alphabet == 95 )
          password_to_string5_uni ( & ns_shifr . raspr5  . password_const ,
            & password_letters , & ns_shifr . letters , letters_count ) ;
        else
          password_to_string5_uni ( & ns_shifr . raspr5  . password_const ,
            & password_letters , & ns_shifr . letters2 , letters_count2 ) ; }
           
      if  ( strcmp ( &(password_letters[0]) , &((*res)[0]) ) )  
        fprintf  ( stderr , ( ns_shifr . localerus ?
          u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
          "Warning! Password \'%s\' is very large. Same as \'%s\'\n" )
          , &((*res)[0]) , & ( password_letters  [ 0 ] ) ) ; }
  FILE  * filefrom  = stdin ;
  FILE  * fileto  = stdout  ;
  if ( flaginputfromfile ) {
    FILE * f = fopen(&((*inputfilename)[0]),&("r"[0]));
    if(f == NULL) {
      int e = errno ; 
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка чтения файла \"%s\" : %s\n" :
        "Error reading file \"%s\" : %s\n" ) , & ( ( * inputfilename ) [ 0 ] ) ,
            strerror  ( e ) ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"Ошибка чтения файла" :
        (char const (*)[]) & "Error reading file" ) ;
      longjmp(ns_shifr  . jump,1); }
    flagclosefilefrom = true ;
    filefrom = f ;    }
  if ( flagoutputtofile ) {
    FILE * f = fopen(&((*outputfilename)[0]),&("w"[0]));
    if(f == NULL) {
      int e = errno ; 
      fprintf(stderr,( ns_shifr . localerus ? u8"Ошибка записи файла \"%s\" : %s\n":
        "Error writing file \"%s\" : %s\n"),&((*outputfilename)[0]),strerror(e));
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"Ошибка записи файла" :
        (char const (*)[]) & "Error writing file" ) ;
      longjmp(ns_shifr  . jump,1); }
    flagclosefileto = true ;
    fileto  = f ;    }
  t_streambuf filebuffrom ;
  streambuf_init  ( & filebuffrom , filefrom )  ;
  t_streambuf filebufto ;
  streambuf_init  ( & filebufto , fileto )  ;
  { uint8_t shifr [ shifr_deshi_size5 ] = { } ;
    // 0 .. 3 - варианты секретных кодов для буквы 0
    // 4 .. 7 - варианты секретных кодов для буквы 1
    // 8 .. b - варианты секретных кодов для буквы 2
    // c .. f - варианты секретных кодов для буквы 3
    // 10 .. 13 - варианты секретных кодов для буквы 4
    // 14 .. 17 - варианты секретных кодов для буквы 5
    // 18 .. 1b - варианты секретных кодов для буквы 6
    // 1c .. 1f - варианты секретных кодов для буквы 7
    uint8_t deshi [ shifr_deshi_size5 ] = { } ;
    if ( ns_shifr . use_version == 4 )  
      password_load ( ns_shifr . raspr4  . password_const  , & shifr , & deshi ) ;
    else
      password_load5 ( & ns_shifr . raspr5  . password_const  , & shifr , & deshi ) ;
# ifdef SHIFR_DEBUG    
  printarr  ( & "shifr" , & shifr , shifr_deshi_size5 ) ;
  printarr  ( & "deshi" , & deshi , shifr_deshi_size5 ) ;
# endif
  if ( flagenc ) {
     // if text / digit
    if ( ns_shifr . use_version == 4 )  {
    int bytecount = 0 ;
    uint8_t old_last_sole = 0 ;
    do {
      char buf ;
      size_t readcount = fread ( & buf , 1 , 1 , filefrom ) ;
      if ( readcount == 0 ) {
        if ( ferror ( filefrom ) ) {
          clearerr ( filefrom ) ;
          ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
            (char const (*)[]) & u8"ошибка чтения файла" :
            (char const (*)[]) & "error reading file" ) ;
          longjmp(ns_shifr  . jump,1); }
        break ; }
      uint8_t const secretdata  [ 4 ] = { [ 0 ]  = buf  bitand 0x3 ,
        [ 1 ] = ( buf >>  2 ) bitand 0x3 , [ 2 ] = ( buf >>  4 ) bitand 0x3 ,
        [ 3 ] = ( buf >>  6 ) bitand 0x3 } ;
      uint8_t secretdatasole  [ 4 ] ;
      datasole ( & secretdata , & secretdatasole , 4 )  ;
      // после подсоления, данные переворачиваем предыдущим ксором
      data_xor ( & old_last_sole , & secretdatasole , 4 )  ;
      uint8_t encrypteddata [ 4 ] ;
      crypt_decrypt ( & secretdatasole , & shifr , & encrypteddata , 4 ) ;
            
      for ( int i = 0 ; i < 4 ; i +=  2 ) {
        buf = ( encrypteddata [ i ] & 0xf ) bitor
          ( ( encrypteddata [ i + 1 ] & 0xf ) << 4  ) ;
        size_t writecount ;
        if(flagtext) {
          char buf2[2];
          char_to_hex(buf,&buf2);
          writecount = fwrite ( & buf2 , 2 , 1 , fileto ) ;
          ++ bytecount ;
          if ( bytecount == 24 )  {
            bytecount = 0 ;
            buf2[0] = '\n' ;
            fwrite ( & (buf2[0]) , 1 , 1 , fileto ) ; }      }
        else
          writecount = fwrite ( & buf , 1 , 1 , fileto ) ;
        if ( writecount == 0 ) {
          if ( ferror ( fileto ) ) {
            clearerr ( fileto ) ;
            ns_shifr  . string_exception  = ( ns_shifr . localerus ?
              (char const (*)[]) & u8"ошибка записи в файл" :
              (char const (*)[]) & "error writing to file" ) ;
            longjmp(ns_shifr  . jump,1); }
          break ; } }
    } while ( true ) ; 
    if ( flagtext and bytecount ) {
      char buf = '\n' ;
      fwrite ( & buf , 1 , 1 , fileto ) ; } } // была 4-ая версия
    else  {
      // версия 5 шифруем ...
      int bitscount  = 0 ;
      uint8_t secretdata  [ 4 ] ;
      uint8_t secretdatasole  [ 3 ] ;
      uint8_t secretdatasolesize  ;
      uint8_t encrypteddata [ 3 ] ;
      bool  feof  = false ;
      uint8_t old_last_sole = 0 ;
    do {
      unsigned  char buf ;
      size_t readcount = fread ( & buf , 1 , 1 , filefrom ) ;
      if ( readcount == 0 ) {
        if ( ferror ( filefrom ) ) {
          clearerr ( filefrom ) ;
          ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
            (char const (*)[]) & u8"ошибка чтения файла" :
            (char const (*)[]) & "error reading file" ) ;
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
        datasole ( & secretdata , & secretdatasole , secretdatasolesize )  ;

        // после подсоления, данные переворачиваем предыдущим ксором
        data_xor ( & old_last_sole , & secretdatasole , secretdatasolesize )  ;

        crypt_decrypt ( & secretdatasole , & shifr , & encrypteddata ,
          secretdatasolesize ) ;
        streambuf_write ( & filebufto , & encrypteddata , secretdatasolesize ,
          flagtext )  ;
        break ; }
      switch  ( bitscount  ) {
      case  0 :
        // <= [ [1 0] [2 1 0] [2 1 0] ]
        secretdata [ 0 ]  = buf  bitand 0x7 ;
        secretdata [ 1 ] = ( buf >>  3 ) bitand 0x7 ;
        secretdata [ 2 ] = ( buf >>  6 ) bitand 0x7 ;
        bitscount  = 2 ; // 0 + 8 - 6
        secretdatasolesize  = 2 ;
        break ;
      case  1 : 
        // <= [ [2 1 0] [2 1 0] [2 1] ] <= [ [0]
        secretdata [ 0 ] = secretdata [ 3 ] bitor (( buf  bitand 0x3 )<<1) ;
        secretdata [ 1 ] = ( buf >>  2 ) bitand 0x7 ;
        secretdata [ 2 ] = ( buf >>  5 ) bitand 0x7 ;
        bitscount  = 0 ;   // 1 + 8 - 9
        secretdatasolesize  = 3 ;
        break ;
      case  2 :
        // <= [ [0] [2 1 0] [2 1 0] [2] ] <= [ [1 0] ..
        secretdata [ 0 ] = secretdata [ 2 ] bitor (( buf  bitand 0x1 )<<2) ;
        secretdata [ 1 ] = ( buf >>  1 ) bitand 0x7 ;
        secretdata [ 2 ] = ( buf >>  4 ) bitand 0x7 ;
        secretdata [ 3 ] = ( buf >>  7 ) bitand 0x7 ;
        bitscount  = 1 ; // 2 + 8 - 9
        secretdatasolesize  = 3 ;
        break ;
      default :
        fprintf ( stderr  , ( ns_shifr . localerus ?
          u8"неожиданное значение bitscount = %d\n":
          "unexpected value bitscount = %d\n" ) , bitscount ) ;
        ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
          (char const (*)[]) & u8"неожиданное значение bitscount" :
          (char const (*)[]) & "unexpected value bitscount" ) ;
        longjmp ( ns_shifr  . jump  , 1 ) ; }
      datasole ( & secretdata , & secretdatasole , secretdatasolesize )  ;
      // после подсоления, данные переворачиваем предыдущим ксором
      data_xor ( & old_last_sole , & secretdatasole , secretdatasolesize )  ;
      crypt_decrypt ( & secretdatasole , & shifr , & encrypteddata ,
        secretdatasolesize ) ;
      streambuf_write ( & filebufto , & encrypteddata , secretdatasolesize ,
        flagtext )  ;
    } while ( not feof ) ; 
    streambuf_writeflushzero ( & filebufto , flagtext ) ; }  // была 5-ая версия 
    } // кодировали
  else  { // декодируем
    if ( ns_shifr . use_version == 4 ) {
      uint8_t old_last_sole = 0 ;
    do {
      char buf [ 2 ] ;
      size_t readcount ;
      if  ( flagtext  ) {
        char buf4 [ 4 ] ;
        // читаем четыре буквы '0a1b' -> декодируем в два байта "XY"
        do {
          readcount = fread ( & (buf4[0]) , 1 , 1 , filefrom ) ;
          if ( readcount == 0 ) {
            if ( feof ( filefrom ) ) goto out ;
            if ( ferror ( filefrom ) ) {
              clearerr ( filefrom ) ;
              ns_shifr  . string_exception  = ( ns_shifr . localerus ?
                (char const (*)[]) & u8"ошибка чтения файла" :
                (char const (*)[]) & "error reading file" ) ;
              longjmp(ns_shifr  . jump,1); }
            goto out ; }
          // если это НЕ цифра и НЕ буква
        } while ( ( buf4[0] < '0' or buf4[0] > '9') and
            ( buf4[0] < 'a' or buf4[0] > 'f') ) ;
        readcount = fread ( & (buf4[1]) , 1 , 3 , filefrom ) ;
        if ( readcount < 3 ) {
          if ( feof ( filefrom ) )
            ns_shifr  . string_exception  = ( ns_shifr . localerus ?
              (char const (*)[]) & u8"ошибка hex данных" :
              (char const (*)[]) & "error hex data" ) ;
          else
            if ( ferror ( filefrom ) ) {
              clearerr ( filefrom ) ;
              ns_shifr  . string_exception  = ( ns_shifr . localerus ?
                (char const (*)[]) & u8"ошибка чтения файла" :
                (char const (*)[]) & "error reading file" ) ; }
            else
              ns_shifr  . string_exception  = ( ns_shifr . localerus ?
                (char const (*)[]) & u8"ошибка hex данных" :
                (char const (*)[]) & "error hex data" ) ;
          longjmp(ns_shifr  . jump,1);  }
        for ( char const * i = &(buf4[1]); i <= &(buf4[3]) ; ++ i ) {
          if (  not ( ( ( * i ) >= '0' and (  * i ) <= '9'  ) or
              ( ( * i ) >= 'a' and (  * i ) <= 'f'  ) ) ) {
            ns_shifr  . string_exception  = ( ns_shifr . localerus ?
              (char const (*)[]) & u8"ошибка hex данных" :
              (char const (*)[]) & "error hex data" ) ;
            longjmp(ns_shifr  . jump,1); } }
        hex_to_char ( ( char const ( * ) [ 2 ] ) ( & buf4 ) ,
          & ( buf [ 0 ] ) ) ;  
        hex_to_char ( ( char const ( * ) [ 2 ] ) ( & ( buf4 [ 2 ] ) ) ,
          & ( buf [ 1 ] ) ) ; }
      else {
        readcount = fread ( & ( buf [ 0 ] ) , 1 , 2 , filefrom ) ;
        if ( readcount < 2 ) {
          if ( feof ( filefrom  ) ) break ;
          if ( ferror ( filefrom ) ) {
            clearerr ( filefrom ) ;
            ns_shifr  . string_exception  = ( ns_shifr . localerus ?
              (char const (*)[]) & u8"ошибка чтения файла" :
              (char const (*)[]) & "error reading file" ) ;
            longjmp(ns_shifr  . jump,1); }
          break ; } }
      uint8_t secretdata  [ 4 ] = { [ 0 ] = buf [ 0 ] bitand  0xf ,
        [ 1 ] = ( buf [ 0 ] >>  4 ) bitand  0xf ,
        [ 2 ] = buf [ 1 ] bitand  0xf ,
        [ 3 ] = ( buf [ 1 ] >>  4 ) bitand  0xf  } ;
      uint8_t decrypteddata [ 4 ] ;
      decrypt_sole ( & secretdata , & deshi , & decrypteddata , 4 ,
        & old_last_sole ) ;
      buf [ 0 ] = ( decrypteddata [ 0 ] bitand 0x3  ) bitor
        ( ( decrypteddata [ 1 ] bitand 0x3  ) << 2  )
        bitor ( ( decrypteddata [ 2 ] bitand 0x3  ) <<  4 ) bitor
        ( ( decrypteddata [ 3 ] bitand 0x3  ) << 6  ) ;
      size_t writecount = fwrite ( & (buf[0]) , 1 , 1 , fileto ) ;
      if ( writecount == 0 ) {
        if ( ferror ( fileto ) ) {
          clearerr ( fileto ) ;
          ns_shifr  . string_exception  = ( ns_shifr . localerus ?
            (char const (*)[]) & u8"ошибка записи файла" :
            (char const (*)[]) & "error writing file" ) ;
          longjmp(ns_shifr  . jump,1); }
        break ; }
    } while ( true ) ; } // ver4
    else { // ver 5
      uint8_t secretdata [ 1 ] ;
      uint8_t old_last_sole = 0 ;
      while ( not isEOFstreambuf_read5bits ( & filebuffrom ,
        & ( secretdata [ 0 ] ) , flagtext ) ) {
        uint8_t decrypteddata [ 1 ] ;
        decrypt_sole ( & secretdata , & deshi , & decrypteddata , 1 ,
          & old_last_sole ) ;
        streambuf_write3bits ( & filebufto , decrypteddata [ 0 ] ) ; } } // ver 5
    }  //  decode 
  } // shifr deshi
out : ;  
  int resulterror  = 0 ;
  if ( flagclosefileto  ) {
    if  ( fclose  ( fileto  ) ) {
      int e = errno ;
      fprintf  (  stderr, ( ns_shifr . localerus ?
        u8"Ошибка закрытия файла записи \"%s\" : %s\n" :
        "Error closing file to writing \"%s\" : %s\n" ) ,
        & ( ( * outputfilename ) [ 0 ] ) , strerror  ( e ) ) ;
      resulterror = 1 ; } }
  if ( flagclosefilefrom ) {
    if  ( ( not feof ( filefrom ) ) and fclose  ( filefrom ) ) {
      int e = errno ; 
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка закрытия файла чтения \"%s\" : %s\n" :
        "Error closing file of reading \"%s\" : %s\n"),
        &((*inputfilename)[0]),strerror(e));
      resulterror = 2 ; } }
  shifr_destr ( ) ;
  return  resulterror ; 
  
}
