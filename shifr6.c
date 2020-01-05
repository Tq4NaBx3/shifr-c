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
// RAND_MAX size 31 bits
// first random 22/31 , second 23/31 
// maximum random < [ 2494190 , 7700480 ] =
//   2494190 * ( 2 ^ 23 ) + 7700480 == 20922789888000

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
# include <sys/time.h>

//# define  SHIFR_DEBUG

# define  arrp  shifr_arrp
typedef uint8_t ( * arrp ) [ ] ;
# define  arrcp  shifr_arrcp
typedef uint8_t const ( * arrcp ) [ ] ;
# define  strp  shifr_strp
typedef char ( * strp ) [ ] ;
# define  strcp  shifr_strcp
typedef char const ( * strcp ) [ ] ;

// четыре * четыре = шестнадцать
# define  shifr_deshi_size2  ((size_t)(0x10U))

// 8 * 8 = 64
# define  shifr_deshi_size6  ((size_t)(0x40U))

# define  initarr shifr_initarr
static inline  void  initarr ( arrp  const p , uint8_t const codefree ,
  size_t const loc_shifr_deshi_size ) {
  uint8_t * i = & ( ( * p ) [ loc_shifr_deshi_size  ] ) ;
  do {
    --  i ;
    ( * i ) = codefree ;
  } while ( i not_eq  & ( ( * p ) [ 0 ] ) ) ; }
  
# ifdef SHIFR_DEBUG
# define  printarr  shifr_printarr
static  void  printarr  ( strcp const  name , arrcp const p ,
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

// 0x20 (пробел) ' '    ---     0x7e (тильда) '~'
// 95 шт
# define letters_count (UINT8_C(('~' - ' ') + 1))

// 0x30 '0' - 0x39 '9' , 0x41 'A' - 0x5a 'Z' , 0x61 'a' - 0x7a 'z'
// 62 шт
# define letters_count2 (UINT8_C( \
  ('9' - '0') + 1 + ('Z' - 'A') + 1 + ('z' - 'a') + 1 ))

# define  t_raspr4  shifr_t_raspr4

typedef struct  s_raspr4 {

uint64_t  password_const  ;

} t_raspr4  ;

typedef struct  s_number320 {
  uint64_t a [ 5 ] ;
} t_number320 ;

typedef struct  s_raspr6 {

t_number320 password_const  ;

} t_raspr6 ;

typedef struct  s_ns_shifr  {

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
strcp string_exception ;

t_raspr4 raspr4 ;
t_raspr6 raspr6 ;

int use_version ; //  4 или 6

FILE  * filefrom  ;
FILE  * fileto  ;
bool  flagtext  ;

uint8_t shifr [ shifr_deshi_size2 ] ;
    uint8_t shifr6 [ shifr_deshi_size6 ] ;
    // варианты секретных кодов для буквы
    // 0 .. 3 - 0
    // 4 .. 7 - 1
    // 8 .. b - 2
    // c .. f - 3
    uint8_t deshi [ shifr_deshi_size2 ] ;
    // варианты секретных кодов для буквы
    // 0 .. 7 -  0
    // 8 .. f -  1
    // 10 .. 17 -  2
    // 18 .. 1f -  3
    // 20 .. 27 -  4
    // 28 .. 2f -  5
    // 30 .. 37 -  6
    // 38 .. 3f -  7
    uint8_t deshi6 [ shifr_deshi_size6 ] ;
} t_ns_shifr ;

static  t_ns_shifr  ns_shifr = {
  . use_version  = 6 ,
  . flagtext = false ,
  . shifr = { } ,
  . deshi = { } ,
  . shifr6 = { } ,
  . deshi6 = { } ,
} ;

static  void  password_to_string_uni ( uint64_t password , strp const string ,
  strp letters , uint8_t const letterscount ) {
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
static uint8_t  number320_div8mod  ( t_number320 * restrict const number ,
  uint8_t const div ) {
  uint64_t res [ 6 ] ;
  ldiv_t  ld  ;

  ld  = ldiv  ( number  ->  a [ 4 ] , div ) ;
  res [ 5 ] =  ld . quot ;
  
  ld  = ldiv  ( ( ld . rem <<  56 ) bitor
    ( number  ->  a [ 3 ] >>  8 ) , div ) ;
  res [ 4 ] = ld . quot ;

  { int i = 3 ;
    do {
      ld  = ldiv  ( ( ld . rem <<  56 ) bitor
        ( ( ( number  ->  a [ i ] ) << ( ( 4 + i ) << 3 ) ) >> 8 ) bitor
        ( number  ->  a [ i - 1 ] >> ( ( 5 - i ) << 3 ) ) , div ) ;
      res [ i ] = ld . quot ;
      -- i ;
    } while ( i >= 1 ) ; }

  ld  = ldiv  ( ( ld . rem <<  32 ) bitor
    ( ( ( number  ->  a [ 0 ] ) << 32 ) >> 32 ) , div ) ;

  number  ->  a [ 0 ] = ld . quot ;

  for ( int i = 1 ; i <= 4 ; ++ i ) {
    { uint64_t const old = number  ->  a [ i - 1 ] ;
      number  ->  a [ i - 1 ] +=  ( res [ i ] << ( ( 5 - i ) << 3 ) ) ;
      if ( number  ->  a [ i - 1 ] < old )  number  ->  a [ i ] = 1 ;
      else  number  ->  a [ i ] = 0 ; }
    number  ->  a [ i ] +=  ( res [ i ] >> ( ( 3 + i ) << 3 ) ) ; }

  number  ->  a [ 4 ] +=  res [ 5 ] ;

  return  ld  . rem ; }

// --
static  inline  void  number320dec  ( t_number320 * const restrict number ) {
  uint64_t  * restrict i = & ( ( number ->  a ) [ 0 ] ) ; 
  do {
    if ( ( * i ) == 0 ) -- ( * i ) ;
    else  {
      -- ( * i ) ;
      break ; }
    ++  i ;
  } while ( i not_eq & ( ( number ->  a ) [ 5 ] ) ) ; }
  
static  inline  bool  number320_not0  (
  t_number320 const * const restrict np ) {
  uint64_t const * i = & ( np -> a [ 5 ] ) ;
  do {
    --  i ;
    if ( * i )  return  true  ;
  } while ( i not_eq & ( np -> a [ 0 ] ) ) ;
  return  false ; }
  
static  void  password_to_string6_uni (
  t_number320 const * const restrict password0 , strp const string ,
  strp letters , uint8_t const letterscount  ) {
  char * stringi = & ( ( * string )  [ 0 ] ) ;
  if ( number320_not0 ( password0 ) ) {
    t_number320 password = * password0  ;
    do {
      // здесь предыдущие размеры заняли место паролей
      number320dec  ( & password  ) ;
      ( * stringi ) = ( * letters ) [ number320_div8mod  ( & password ,
        letterscount ) ] ;
      ++  stringi ;
    } while ( number320_not0 ( & password ) ) ; }
  ( * stringi ) = '\00' ;  }

static  void  string_to_password_uni ( strcp const string ,
  uint64_t * const password , strp letters ,
  uint8_t const letterscount ) {
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
  
static  inline  void number320_set0  ( t_number320 * const restrict np ) {
  memset  ( & ( ( np -> a ) [ 0 ] ) , 0 , 5 * sizeof  ( uint64_t  ) ) ; }

static  inline  void number320_setUInt  ( t_number320 * const restrict np ,
  unsigned int const x ) {
  memset  ( & ( ( np -> a ) [ 1 ] ) , 0 , 4 * sizeof  ( uint64_t  ) ) ;
  ( np -> a ) [ 0 ] = x ; }

static  void number320_add  (
  t_number320 * const restrict np , t_number320 const * const restrict xp ) {
  if ( np == xp ) {
    t_number320 tmp = * xp ;
    number320_add ( np , & tmp ) ;
    return ; }
  uint64_t pere = 0 ;
  for ( int i = 0 ; i < 5 ; ++ i ) {
    uint64_t pere2  = 0 ;
    { uint64_t old = np  ->  a [ i ] ;
      ( np  ->  a [ i ] ) +=  ( xp  ->  a [ i ] ) ; 
      if (  np  ->  a [ i ] < old ) pere2 = 1; 
      else  pere2 = 0 ; }
    uint64_t  old = np  ->  a [ i ] ;
    ( np  ->  a [ i ] ) +=  pere  ;
    if ( np  ->  a [ i ] < old ) pere = 1 ;
    else  pere  = pere2 ; } }
  
static void  number320_mul8  ( t_number320 * const restrict np , uint8_t const m ) {
  uint64_t  r [ 6 ] ;
  r  [ 0 ] = ( ( ( ( np  ->  a [ 0 ] ) << 8 ) >> 8 ) * ( ( uint64_t  ) m ) ) ;
  for ( int i = 1 ; i <= 4 ; ++ i )
    r  [ i ] = ( ( ( np  ->  a [ i - 1 ]  ) >> ( ( 8 - i ) << 3 ) ) bitor
      ( ( ( np  ->  a [ i ]  ) <<  ( ( 1 + i ) << 3 ) ) >> 8 ) ) *
      ( ( uint64_t  ) m ) ;
  r  [ 5 ] = ( ( np  ->  a [ 4 ]  ) >> 24 ) * ( ( uint64_t  ) m ) ;
  np  ->  a [ 0 ] = r [ 0 ] ;
  uint64_t  tmp = np  ->  a [ 0 ] ;
  np  ->  a [ 0 ] += ( r [ 1 ] << 56 ) ;
  for ( int i = 1 ; i <= 4 ; ++ i ) {
    if ( np  ->  a [ i - 1 ] < tmp )  np  ->  a [ i ] = 1 ;
    else  np  ->  a [ i ] = 0 ;
    np  ->  a [ i ] += ( r [ i ] >> ( i << 3 ) ) ;
    tmp = np  ->  a [ i ] ;
    np  ->  a [ i ] += ( r [ i + 1 ] << ( ( 7 - i ) << 3 ) ) ; } }

static  void  string_to_password6_uni ( strcp const string ,
  t_number320 * const restrict password , char const (  * const letters ) [ ] ,
    uint8_t const letterscount ) {
  char const * restrict stringi = & ( ( * string )  [ 0 ] ) ;
  if  ( ( * stringi ) == '\00' ) {
    number320_set0 ( password  ) ;
    return ; }
  t_number320  pass ;
  number320_set0  ( & pass  ) ;
  t_number320  mult ;
  number320_setUInt ( & mult , 1 ) ;
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
    { t_number320  tmp = mult ;
      number320_mul8  ( & tmp , i + 1 ) ;
      number320_add ( &  pass  , & tmp )  ; }
    number320_mul8  ( & mult , letterscount ) ;
    ++  stringi ;
  } while ( ( * stringi ) not_eq '\00' ) ;
  ( * password  ) = pass ; }
  
static inline void  shifr_init ( void  ) {
  { char * j = & ( ns_shifr . letters [ 0 ] ) ;
    for ( uint8_t i = ' ' ; i <= '~' ; ++ i , ++ j ) ( * j ) = i ;  }
  // 0x30 '0' - 0x39 '9' , 0x41 'A' - 0x5a 'Z' , 0x61 'a' - 0x7a 'z'  
  { char * j = & ( ns_shifr . letters2 [ 0 ] ) ;
    for ( uint8_t i = '0' ; i <= '9' ; ++ i , ++ j ) ( * j ) = i ;
    for ( uint8_t i = 'A' ; i <= 'Z' ; ++ i , ++ j ) ( * j ) = i ;
    for ( uint8_t i = 'a' ; i <= 'z' ; ++ i , ++ j ) ( * j ) = i ; }
  ns_shifr  . filefrom  = stdin ;
  ns_shifr  . fileto = stdout ; }
  
// пароль раскладываем в таблицу шифровки , дешифровки
  // пароль % 0x10 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  // пароль делим на 16, остаются 15! вариантов пароля
  // пароль % 0xf = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
  // секретных кодов для соли+данных 0x1  
// в deshi нужна соль
static inline void  password_load ( uint64_t password , 
  arrp const shifrp , arrp const deship ) {
# define  codefree  ((uint8_t)0xff)
  initarr ( shifrp , codefree , shifr_deshi_size2 )  ;
  initarr ( deship , codefree , shifr_deshi_size2 )  ;
# undef codefree
  uint8_t arrind  [ shifr_deshi_size2  ] ;
  { uint8_t * arrj  = & ( arrind  [ shifr_deshi_size2  ] ) ;
    uint8_t j = shifr_deshi_size2  ;
    do  {
      --  arrj  ;
      --  j ;
      ( * arrj )  = j ;
    } while ( arrj  not_eq & ( arrind  [ 0 ] ) ) ;  }
  // 0 .. 15
  uint8_t inde  = 0 ;
  do  {
    { uint8_t cindex  ;
      { ldiv_t di = ldiv ( password  , shifr_deshi_size2  - inde ) ;
        cindex  = di . rem ;
        password  = di  . quot  ; }
      uint8_t * arrind_cindexp = & (  arrind [ cindex ] ) ;
      ( * shifrp  ) [ inde ] = ( * arrind_cindexp ) ;
      ( * deship  ) [ * arrind_cindexp ] = inde ;
      memmove ( arrind_cindexp , arrind_cindexp + 1 ,
        shifr_deshi_size2  - inde  - cindex - 1 ) ; }
    ++  inde  ;
  } while ( inde  < shifr_deshi_size2  ) ; }

# ifdef SHIFR_DEBUG
//  /= 64  или  >>= 6
static inline void  number320_shift_down  ( t_number320 * const nump ,
  uint8_t const s ) {
  uint64_t * p = & ( nump -> a [ 5 ] ) ;
  uint8_t  old6 = 0 ;
  do {
    --  p ;
    uint8_t const new6  = ( * p ) bitand (  ( 1U  <<  s ) - 1 ) ;
    ( * p ) = ( ((uint64_t)old6) << ( 64  - s ) ) bitor ( ( * p ) >> s ) ;
    old6 = new6 ;
  } while ( p not_eq & ( nump -> a [ 0 ] ) ) ;  }
# endif

// пароль раскладываем в таблицу шифровки , дешифровки
  // пароль % 0x10 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  // пароль делим на 64, остаются 63! вариантов пароля
  // пароль % 0xf = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
  // секретных кодов для соли+данных 0x1  
// в deshi нужна соль
static inline void  password_load6 ( t_number320 const * const password_constp ,
  arrp const shifrp , arrp const deship ) {
# define  codefree ((uint8_t)0xffU)
  initarr ( shifrp , codefree , shifr_deshi_size6 )  ;
  initarr ( deship , codefree , shifr_deshi_size6 )  ;
# undef codefree
  t_number320  password = * password_constp ;
  uint8_t arrind  [ shifr_deshi_size6 ] ;
  { uint8_t * arrj  = & ( arrind  [ shifr_deshi_size6 ] ) ;
    uint8_t j = shifr_deshi_size6  ;
    do  {
      --  arrj  ;
      --  j ;
      ( * arrj )  = j ;
    } while ( arrj  not_eq & ( arrind  [ 0 ] ) ) ; }
  // 0 .. 63
  uint8_t inde  = 0 ;
  do  {
    uint8_t cindex  = number320_div8mod  ( & password , shifr_deshi_size6  - inde ) ;
    uint8_t * arrind_cindexp = & (  arrind [ cindex ] ) ;
    ( * shifrp  ) [ inde ] = (  * arrind_cindexp  ) ;
    ( * deship  ) [ * arrind_cindexp ] = inde ;
    memmove ( arrind_cindexp , arrind_cindexp + 1 ,
      shifr_deshi_size6  - inde  - cindex - 1 ) ;
    ++  inde  ;
  } while ( inde  < shifr_deshi_size6  ) ; }

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

static  inline  void  char_to_hex ( char  buf , char ( * const buf2 ) [ 2 ] ) {
  unsigned  char c = buf bitand 0xf ;
  if ( c <= 9 ) ( * buf2  ) [ 0 ] = '0' + c ;
  else  ( * buf2  ) [ 0 ] = 'a' + ( c - 10  ) ;
  c = ( buf >> 4  ) bitand 0xf ;
  if ( c <= 9 ) ( * buf2  ) [ 1 ] = '0' + c ;
  else  ( * buf2  ) [ 1 ] = 'a' + ( c - 10  ) ; }

// ';' = 59 ... 'z' = 122 , 122 - 59 + 1 == 64
static  inline  char  bits6_to_letter ( uint8_t const bits6 ) {
  return  ';'  + bits6  ; }

static  inline  uint8_t letter_to_bits6 ( char  const letter  ) {
  return  letter  - ';' ; }

static  void  hex_to_char ( char const ( * restrict const buf2 ) [ 2 ] ,
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
static void set_keypress (void) {
  if  ( tcgetattr ( 0 , & ns_shifr  . stored_termios  ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifr . localerus ?
      u8"ошибка чтения tcgetattr : %s\n" :
      "error read tcgetattr : %s\n" ) ,se ) ;
    ns_shifr  . string_exception  = (char const (*)[])se ;
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
    ns_shifr  . string_exception  = (char const (*)[])se ;
    longjmp(ns_shifr  . jump,1); } }
 
// Восстановление дефолтного состояния
static void reset_keypress (void) {
  if  ( tcsetattr ( 0 , TCSANOW , & ns_shifr . stored_termios ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifr . localerus ?
      u8"ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifr  . string_exception  = (char const (*)[]) se ;
    longjmp(ns_shifr  . jump,1); } }  
  
# define  t_streambuf shifr_t_streambuf
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
  
// читаю 6 бит
static inline bool  isEOFstreambuf_read6bits ( t_streambuf * const restrict me  ,
  uint8_t * const encrypteddata , bool const  flagtext ) {
  if  ( ( not flagtext ) and streambuf_bufbitsize  ( me  ) >= 6 ) {
    streambuf_bufbitsize  ( me  ) -=  6 ;
    ( * encrypteddata ) = streambuf_buf ( me  ) bitand (0x40 - 1) ;
    streambuf_buf ( me  ) >>= 6 ;
    return  false ; }
  uint8_t buf ;
  { size_t  const nreads  = fread ( & buf , 1 , 1 , streambuf_file  ( me  ) ) ;
    if ( nreads ==  0 ) {
      if  ( feof  ( streambuf_file  ( me  ) ) ) return  true  ;
      if  ( ferror  ( streambuf_file  ( me  ) ) ) {
        clearerr ( streambuf_file  ( me  ) ) ;
        ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
          (char const (*)[]) &
          u8"isEOFstreambuf_read6bits: ошибка чтения шести бит" :
          (char const (*)[]) & "isEOFstreambuf_read6bits: six bits read error" ) ;
        longjmp(ns_shifr  . jump,1); } } } // nreads

  if  ( flagtext  ) {
    // читаем одну букву ';'-'z' -> декодируем в шесть бит
    while ( ( buf < ((uint8_t)';') ) or ( buf > ((uint8_t)'z') ) ) {
      { size_t  const nreads  = fread ( & buf , 1 , 1 , streambuf_file  ( me  ) ) ;
        if ( nreads ==  0 ) {
          if  ( feof  ( streambuf_file  ( me  ) ) ) return  true  ;
          if  ( ferror  ( streambuf_file  ( me  ) ) ) {
            clearerr ( streambuf_file  ( me  ) ) ;
            ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
              (char const (*)[]) &
              u8"isEOFstreambuf_read6bits: ошибка чтения шести бит из текста" :
              (char const (*)[]) &
              "isEOFstreambuf_read6bits: six bits read error from text" ) ;
            longjmp(ns_shifr  . jump,1); } } } // nreads
          } //  while not digit and not letter
    ( * encrypteddata ) = letter_to_bits6 ( buf ) ; }
  else  {
    ( * encrypteddata ) = ( streambuf_buf ( me  ) bitor 
      ( buf <<  streambuf_bufbitsize  ( me  ) ) ) bitand ( 0x40 - 1 )  ;
    streambuf_buf ( me  ) = buf >>  ( 6 - streambuf_bufbitsize  ( me  ) ) ;
    streambuf_bufbitsize  ( me  ) +=  2 ; } // + 8 - 6
  return  false ; }
        
// пишу по шесть бит
// secretdatasolesize количество шести-битных отделов (2 или 3)
// encrypteddata массив шести-битных чисел
static void  streambuf_write6 ( t_streambuf * const restrict me  ,
  uint8_t const (  * const encrypteddata ) [ 3 ] ,
  uint8_t const secretdatasolesize , bool const  flagtext ) {
  for ( uint8_t i = 0 ; i < secretdatasolesize ; ++  i ) {
    if  ( flagtext  ) {
        char  buf2  = bits6_to_letter ( ( * encrypteddata ) [ i ] ) ;
        size_t  writen_count  ;
        writen_count  = fwrite  ( & buf2  , 1 , 1 , streambuf_file  ( me  ) ) ;
        if  ( writen_count  ==  0 ) {
          clearerr  ( streambuf_file  ( me  ) ) ; 
          ns_shifr  . string_exception  = ( ns_shifr  . localerus ? 
            ( char  const ( * ) [ ] ) & u8"streambuf_write6: ошибка записи байта"  :
            ( char  const ( * ) [ ] ) & "streambuf_write6: byte write error" ) ;
          longjmp ( ns_shifr  . jump  , 1 ) ; }
        ++  streambuf_bytecount ( me  ) ;
        if  ( streambuf_bytecount ( me  ) >=  60  ) {
          streambuf_bytecount ( me  ) = 0 ;
          buf2  = '\n'  ;
          writen_count  = fwrite  ( & buf2  , 1 , 1 ,
            streambuf_file  ( me  ) ) ; }
        
         } else {

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
          (char const (*)[]) & u8"streambuf_write6: ошибка записи байта" :
          (char const (*)[]) & "streambuf_write6: byte write error" ) ;
        longjmp(ns_shifr  . jump,1); }
      
        // + 6 - 8
        streambuf_bufbitsize  ( me  ) -= 2 ;
        streambuf_buf ( me  ) = ( ( * encrypteddata ) [ i ] ) >>
          ( 6 - streambuf_bufbitsize  ( me  ) ) ;  } } } }

static inline void  streambuf_writeflushzero ( t_streambuf * const restrict me ,
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
  
// версия 6 пишу три бита для расшифровки
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

static  inline  void  enter_password4 ( int const password_alphabet ) {
  char p40 [ 20 ] ;
  set_keypress  ( ) ;
  char ( * const p4 ) [ 20 ] = (char(*const)[20])
    fgets ( & ( p40 [ 0 ] ) , 20 , stdin ) ;
  reset_keypress ( ) ;
  char * j = & ( ( * p4 ) [ 0 ]  ) ;
  while ( ( ( * j ) not_eq '\n' ) and ( ( * j ) not_eq '\00' ) and
    ( j < ( & ( * p4 ) [ 20 ] ) ) )
    ++ j ;  
  if ( j < ( & ( ( * p4 ) [ 20 ] ) ) )
    ( * j ) = '\00' ;
  else  {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      (char const (*)[]) & u8"в пароле нет конца строки" :
      (char const (*)[]) & "there is no end of line in the password" ) ;
    longjmp(ns_shifr  . jump,1); }
  if ( password_alphabet == 95 )
    string_to_password_uni ( p4 , & ns_shifr . raspr4  . password_const ,
      & ns_shifr . letters ,  letters_count ) ;
  else
    string_to_password_uni ( p4 , & ns_shifr . raspr4  . password_const ,
      & ns_shifr . letters2 , letters_count2 ) ;
  char  password_letters [ 20 ] ;
  if ( password_alphabet == 95 )
    password_to_string_uni ( ns_shifr . raspr4  . password_const ,
      & password_letters , & ns_shifr . letters , letters_count ) ;
  else
    password_to_string_uni ( ns_shifr . raspr4  . password_const ,
      & password_letters , & ns_shifr . letters2 , letters_count2 ) ;
  if  ( strcmp ( &(password_letters[0]) , &((*p4)[0]) ) )  
    fprintf  ( stderr , ( ns_shifr . localerus ?
      u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
      "Warning! Password \'%s\' is very large. Same as \'%s\'\n" )
      , &((*p4)[0]) , & ( password_letters [ 0 ] ) ) ; }

static  inline  void  enter_password6 ( int const password_alphabet ) {
  char p60 [ 100 ] ;
  set_keypress  ( ) ;
  char ( * const p6 ) [ 100 ] = (char(*const)[100])
    fgets ( & ( p60 [ 0 ] ) , 100 , stdin ) ;
  reset_keypress ( ) ;
  char * j = & ( ( * p6 ) [ 0 ]  ) ;
  while ( ( ( * j ) not_eq '\n' ) and ( ( * j ) not_eq '\00' ) and
    ( j < ( & ( * p6 ) [ 100 ] ) ) )
    ++ j ;  
  if ( j < ( & ( ( * p6 ) [ 100 ] ) ) )
    ( * j ) = '\00' ;
  else  {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      (char const (*)[]) & u8"в пароле нет конца строки" :
      (char const (*)[]) & "there is no end of line in the password" ) ;
    longjmp(ns_shifr  . jump,1); }
  if ( password_alphabet == 95 )
    string_to_password6_uni ( p6 , & ns_shifr . raspr6  . password_const ,
      & ns_shifr . letters ,  letters_count ) ;
  else
    string_to_password6_uni ( p6 , & ns_shifr . raspr6  . password_const ,
      & ns_shifr . letters2 , letters_count2 ) ;
  char  password_letters6 [ 100 ] ;
  if ( password_alphabet == 95 )
    password_to_string6_uni ( & ns_shifr . raspr6  . password_const ,
      & password_letters6 , & ns_shifr . letters , letters_count ) ;
  else
    password_to_string6_uni ( & ns_shifr . raspr6  . password_const ,
      & password_letters6 , & ns_shifr . letters2 , letters_count2 ) ;
  if  ( strcmp ( &(password_letters6[0]) , &((*p6)[0]) ) )  
    fprintf  ( stderr , ( ns_shifr . localerus ?
      u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'.\n" :
      "Warning! Password \'%s\' is very large. Same as \'%s\'.\n" )
      , &((*p6)[0]) , & ( password_letters6  [ 0 ] ) ) ; }

void  shifr_encode4 ( void ) {
    int bytecount = 0 ;
    uint8_t old_last_data = 0 ;
    uint8_t old_last_sole = 0 ;
    do {
      char buf ;
      size_t readcount = fread ( & buf , 1 , 1 , ns_shifr  . filefrom ) ;
      if ( readcount == 0 ) {
        if ( ferror ( ns_shifr  . filefrom ) ) {
          clearerr ( ns_shifr  . filefrom ) ;
          ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
            (char const (*)[]) & u8"ошибка чтения файла" :
            (char const (*)[]) & "error reading file" ) ;
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
      crypt_decrypt ( & secretdatasole , & ns_shifr  . shifr , & encrypteddata , 4 ) ;
      for ( int i = 0 ; i < 4 ; i +=  2 ) {
        buf = ( encrypteddata [ i ] & 0xf ) bitor
          ( ( encrypteddata [ i + 1 ] & 0xf ) << 4  ) ;
        size_t writecount ;
        if  ( ns_shifr  . flagtext  ) {
          char buf2 [ 2 ] ;
          char_to_hex ( buf , & buf2  ) ;
          writecount = fwrite ( & buf2 , 2 , 1 , ns_shifr  . fileto ) ;
          ++ bytecount ;
          if ( bytecount == 30 )  {
            bytecount = 0 ;
            buf2[0] = '\n' ;
            fwrite ( & (buf2[0]) , 1 , 1 , ns_shifr  . fileto ) ; }      }
        else
          writecount = fwrite ( & buf , 1 , 1 , ns_shifr  . fileto ) ;
        if ( writecount == 0 ) {
          if ( ferror ( ns_shifr  . fileto ) ) {
            clearerr ( ns_shifr  . fileto ) ;
            ns_shifr  . string_exception  = ( ns_shifr . localerus ?
              (char const (*)[]) & u8"ошибка записи в файл" :
              (char const (*)[]) & "error writing to file" ) ;
            longjmp(ns_shifr  . jump,1); }
          break ; } }
    } while ( true ) ; 
    if ( ns_shifr  . flagtext and bytecount ) {
      char buf = '\n' ;
      fwrite ( & buf , 1 , 1 , ns_shifr  . fileto ) ; } }

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
    do {
      unsigned  char buf ;
      size_t readcount = fread ( & buf , 1 , 1 , ns_shifr  . filefrom ) ;
      if ( readcount == 0 ) {
        if ( ferror ( ns_shifr  . filefrom ) ) {
          clearerr ( ns_shifr  . filefrom ) ;
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
        datasole6 ( & secretdata , & secretdatasole , secretdatasolesize )  ;
        // после подсоления, данные переворачиваем предыдущим ксором
        data_xor6 ( & old_last_data , & old_last_sole , & secretdatasole , secretdatasolesize )  ;
        crypt_decrypt ( & secretdatasole , & ns_shifr  . shifr6 , & encrypteddata ,
          secretdatasolesize ) ;
        streambuf_write6 ( & shifr_filebufto , & encrypteddata , secretdatasolesize ,
          ns_shifr  . flagtext )  ;
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
      datasole6 ( & secretdata , & secretdatasole , secretdatasolesize )  ;
      // после подсоления, данные переворачиваем предыдущим ксором
      data_xor6 ( & old_last_data , & old_last_sole , & secretdatasole ,
        secretdatasolesize )  ;
      crypt_decrypt ( & secretdatasole , & ns_shifr  . shifr6 , & encrypteddata ,
        secretdatasolesize ) ;
      streambuf_write6 ( & shifr_filebufto , & encrypteddata , secretdatasolesize ,
        ns_shifr  . flagtext )  ;
    } while ( not feof ) ; 
    streambuf_writeflushzero ( & shifr_filebufto , ns_shifr  . flagtext ) ; }

void shifr_decode4  ( void  ) {
      uint8_t old_last_data = 0 ;
      uint8_t old_last_sole = 0 ;
    do {
      char buf [ 2 ] ;
      size_t readcount ;
      if  ( ns_shifr  . flagtext  ) {
        char buf4 [ 4 ] ;
        // читаем четыре буквы '0a1b' -> декодируем в два байта "XY"
        do {
          readcount = fread ( & (buf4[0]) , 1 , 1 , ns_shifr  . filefrom ) ;
          if ( readcount == 0 ) {
            if ( feof ( ns_shifr  . filefrom ) ) return ;
            if ( ferror ( ns_shifr  . filefrom ) ) {
              clearerr ( ns_shifr  . filefrom ) ;
              ns_shifr  . string_exception  = ( ns_shifr . localerus ?
                (char const (*)[]) & u8"ошибка чтения файла" :
                (char const (*)[]) & "error reading file" ) ;
              longjmp(ns_shifr  . jump,1); }
            return ; }
          // если это НЕ цифра и НЕ буква
        } while ( ( buf4[0] < '0' or buf4[0] > '9') and
            ( buf4[0] < 'a' or buf4[0] > 'f') ) ;
        readcount = fread ( & (buf4[1]) , 1 , 3 , ns_shifr  . filefrom ) ;
        if ( readcount < 3 ) {
          if ( feof ( ns_shifr  . filefrom ) )
            ns_shifr  . string_exception  = ( ns_shifr . localerus ?
              (char const (*)[]) & u8"ошибка hex данных" :
              (char const (*)[]) & "error hex data" ) ;
          else
            if ( ferror ( ns_shifr  . filefrom ) ) {
              clearerr ( ns_shifr  . filefrom ) ;
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
        readcount = fread ( & ( buf [ 0 ] ) , 1 , 2 , ns_shifr  . filefrom ) ;
        if ( readcount < 2 ) {
          if ( feof ( ns_shifr  . filefrom  ) ) break ;
          if ( ferror ( ns_shifr  . filefrom ) ) {
            clearerr ( ns_shifr  . filefrom ) ;
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
            (char const (*)[]) & u8"ошибка записи файла" :
            (char const (*)[]) & "error writing file" ) ;
          longjmp(ns_shifr  . jump,1); }
        break ; }
    } while ( true ) ; }

void shifr_decode6 ( void ) {
      uint8_t secretdata [ 1 ] ;
      uint8_t old_last_data = 0 ;
      uint8_t old_last_sole = 0 ;
      while ( not isEOFstreambuf_read6bits ( & shifr_filebuffrom ,
        & ( secretdata [ 0 ] ) , ns_shifr  . flagtext ) ) {
        uint8_t decrypteddata [ 1 ] ;
        decrypt_sole6 ( & secretdata , & ns_shifr  . deshi6 , & decrypteddata , 1 ,
          & old_last_sole , & old_last_data ) ;
        streambuf_write3bits ( & shifr_filebufto , decrypteddata [ 0 ] ) ; } }

void  shifr_password_generate4 ( void ) {
  int r1 , r0 ;
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
        // последний элемент солю микросекундами
        struct timeval currentTime  ;
        gettimeofday  ( & currentTime , NULL  ) ;
        r0 xor_eq ( currentTime . tv_usec ) ;
      } while ( ( r1 ==  shifrrandmax1  ) and ( r0 >= shifrrandmax0 ) ) ;
      ns_shifr . raspr4  . password_const = ( ( ( uint64_t  ) r1  ) <<  23 ) bitor
        ( ( uint64_t  ) r0 ) ;
# undef shifrrandmax0
# undef shifrrandmax1
  }

void  shifr_password_generate6 ( void ) {
  int const rmax  [ 10 ] = { 0 , 0 , 371982424 , 465456948 , 36645132 ,
          851424078 , 78362151 , 525642490 , 110135612 , 535066862 } ;
        int r [ 10  ] ;
rand6try :
        { int * ri  = & ( r [ 10  ] ) ;
          do {
            -- ri ;
            ( * ri ) = rand ( ) >> 2 ;
          } while ( ri not_eq ( & ( r [ 6 ] ) ) ) ;
          // последний элемент солю микросекундами
          struct timeval currentTime  ;
          gettimeofday  ( & currentTime , NULL  ) ;
          r [ 9 ] xor_eq ( currentTime . tv_usec ) ;
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
              if ( ( * ri ) > ( * rmaxi ) ) goto rand6try ; 
            } while ( ri not_eq ( & ( r [ 2 ] ) ) ) ; } }
        goto  rand6try ;
rand6ok :
# ifdef SHIFR_DEBUG
      fputs ( ns_shifr . localerus ? u8"внутренний пароль = [ "  :
        "inner password = [ " , stderr ) ;
      for ( int const * i = & ( r [ 10 ] ) ; i not_eq & ( r [ 0 ] ) ;  ) {
        --  i ;
        fprintf (stderr, "%x , " , * i ) ;  }
      fputs  ( "]\n",stderr ) ;
# endif
      // [ 0  .. 29 , 0 .. 29 , 0 .. 3  ]
      // [ 4  .. 29 , 0 .. 29 , 0 .. 7  ]
      // [ 8  .. 29 , 0 .. 29 , 0 .. 11 ]
      // [ 12 .. 28 , 0 .. 28 , 0 .. 17 ]
      // [ 18 .. 28 , 0 .. 28 ]
      ns_shifr . raspr6  . password_const . a [ 0 ] =
        ((uint64_t)( r [ 0 ] bitand  ( ( 1U <<  30 ) - 1 ) )) bitor 
        ( ((uint64_t)( r [ 1 ] bitand  ( ( 1U <<  30 ) - 1 ) )) << 30 ) bitor
        ( ((uint64_t)( r [ 2 ] bitand ( ( 1U << 4 ) - 1 ) )) << 60  ) ;
      ns_shifr . raspr6  . password_const . a [ 1 ] =
        ((uint64_t)( ( r [ 2 ] >> 4 ) bitand  ( ( 1U <<  26 ) - 1 ) )) bitor 
        ( ((uint64_t)( r [ 3 ] bitand  ( ( 1U <<  30 ) - 1 ) )) << 26 ) bitor
        ( ((uint64_t)( r [ 4 ] bitand ( ( 1U << 8 ) - 1 ) )) << 56  ) ;
      ns_shifr . raspr6  . password_const . a [ 2 ] =
        ((uint64_t)( ( r [ 4 ] >> 8 ) bitand  ( ( 1U <<  22 ) - 1 ) )) bitor 
        ( ((uint64_t)( r [ 5 ] bitand  ( ( 1U <<  30 ) - 1 ) )) << 22 ) bitor
        ( ((uint64_t)( r [ 6 ] bitand ( ( 1U << 12 ) - 1 ) )) << 52  ) ;
      ns_shifr . raspr6  . password_const . a [ 3 ] =
        ((uint64_t)( ( r [ 6 ] >> 12 ) bitand  ( ( 1U <<  17 ) - 1 ) )) bitor 
        ( ((uint64_t)( r [ 7 ] bitand  ( ( 1U <<  29 ) - 1 ) )) << 17 ) bitor
        ( ((uint64_t)( r [ 8 ] bitand ( ( 1U << 18 ) - 1 ) )) << 46  ) ;
      ns_shifr . raspr6  . password_const . a [ 4 ] =
        ((uint64_t)( ( r [ 8 ] >> 18 ) bitand  ( ( 1U <<  11 ) - 1 ) )) bitor 
        ( ((uint64_t)( r [ 9 ] bitand  ( ( 1U <<  29 ) - 1 ) )) << 11 ) ; }

int main  ( int argc , char * argv [ ] )  {
  char const * const locale = setlocale ( LC_ALL  , ""  ) ;
  ns_shifr . localerus = ( strcmp  ( locale  , "ru_RU.UTF-8" ) ==  0 ) ;
  int exc = setjmp  ( ns_shifr  . jump  ) ;
  if ( exc ) {
    fprintf ( stderr  , ( ns_shifr . localerus ? u8"Исключение : %s\n" :
      "Exception : %s\n" ) , & ( ( *  ns_shifr  . string_exception ) [ 0 ] ) ) ;
    return  1 ; }
  bool  flagenc = false ;
  bool  flagdec = false ;
  bool  flagpasswd  = false ;
  bool  flaggenpasswd  = false ;
  bool  flagreadpasswd  = false ;
  bool  flagreadinput = false ;
  bool  flagreadoutput = false ;
  bool  flagreadpasswdfromfile  = false ;
  strcp inputfilename = & u8""  ;
  strcp outputfilename  = & u8""  ;
  bool  flaginputfromfile = false ;
  bool  flagoutputtofile  = false ;
  bool  flagclosefilefrom = false ;
  bool  flagclosefileto = false ;
  int password_alphabet = 62 ;
  shifr_init  ( ) ;
  if  ( argc  <=  1  ) {
    puts ( ns_shifr . localerus ?
      u8"Шифр6 ©2020 Глебов А.Н.\n"
      u8"Симметричное поточное шифрование с 'солью'.\n"
      u8"'Соль' генерируется постоянно, что даёт хорошую стойкость.\n"
      u8"Размер данных увеличивается в два раза.\n"
      u8"Нет диагностики неправильного пароля.\n"
      u8"Синтаксис : shifr6 [параметры]" :
      "Shifr6 ©2020 Glebe A.N.\n"
      "Symmetric stream encryption with 'salt'.\n"
      "'Salt' is constantly generated, which gives good durability.\n"
      "Data size doubles.\n"
      "There is no diagnosis of the wrong password.\n"
      "Syntax : shifr6 [options]" ) ;
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
      u8"  --пар или\n  --pas 'строка_пароля'\tиспользовать данный пароль" :
      "  --pas 'password_string'\tuse this password" );
    puts  ( ns_shifr . localerus ?
      u8"  --пар-путь или\n  --pas-path 'путь_к_файлу_с_паролем'\tиспользовать пароль в файле" :
      "  --pas-path 'path_to_password_file'\tuse password in file" );
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
      u8"  --4\tиспользовать четырёх битное шифрование, ключ = 45 бит ( семь/восемь букв )." :
      "  --4\tusing four bit encryption, key = 45 bits ( seven/eight letters )." ) ;
    puts  ( ns_shifr . localerus ?
      u8"  --6\tиспользовать шести битное шифрование, ключ = 296 бит ( 46 - 50 букв ). ( по-умолчанию )" :
      "  --6\tusing six bit encryption, key = 296 bits ( 46 - 50 letters ). ( by default )") ;
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
    puts  ( ns_shifr  . localerus ? u8"  $ ./shifr6 --ген-пар > psw"  :
      "  $ ./shifr6 --gen-pas > psw"  ) ;
    puts  ( 
      "  $ cat psw\n"
      "  n3LTQH4eIicGDNaF8CDVRGdaCEVXxPPgikJ9lbQKW4zs8StkhD"  ) ;
    puts  ( ns_shifr  . localerus ?
      u8"  $ ./shifr6 --пар-путь 'psw' > test.e --текст"  :
      "  $ ./shifr6 --pas-path 'psw' > test.e --text"  ) ;
    puts( ns_shifr  . localerus ? u8"  2+2 (Нажимаем Enter,Ctrl+D)" :
      "  2+2 (Press Enter,Ctrl+D)" ) ;
    puts  ( 
      "  $ cat test.e\n"
      "  ylQ?ncm;ags" ) ;
    puts( ns_shifr  . localerus ?
      u8"  $ ./shifr6 --пар-путь 'psw' < test.e --текст --расшифр" :
      "  $ ./shifr6 --pas-path 'psw' < test.e --text --decrypt" ) ;
    puts  ( "  2+2" ) ;
    return 0 ; }
# if  RAND_MAX  !=  0x7fffffff
# error RAND_MAX  !=  0x7fffffff
# endif
  // 31 бит
  srand ( time  ( 0 ) ) ;
  for ( int argj = 1 ; argv [ argj ] ; ++ argj ) {
if ( flagreadpasswdfromfile ) {
    FILE * const f = fopen  ( argv  [ argj  ] , & ( "r" [ 0 ] ) ) ;
    if  ( f == NULL ) {
      int const e = errno ; 
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка открытия файла \"%s\" : %s\n" :
        "Error opening file \"%s\" : %s\n" ) , argv  [ argj  ] ,
            strerror  ( e ) ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( char const (  * ) [ ] ) & u8"Ошибка открытия файла" :
        ( char const (  * ) [ ] ) & "Error opening file" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; }
    clearerr  ( f ) ;
    char  password_letters [ 20 ] ;
    char  password_letters6 [ 100 ] ;
    size_t nr;
    size_t  ns ;
    if ( ns_shifr . use_version == 4 ) {
      ns  = 20 ;
      nr = fread  ( & password_letters , 1 , ns , f ) ; }
    else {
      ns  = 100 ;
      nr = fread  ( & password_letters6 , 1 , ns , f ) ; }
    if ( nr >= ns )  {
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( char const (  * ) [ ] ) & u8"Файл пароля очень большой" :
        ( char const (  * ) [ ] ) & "Password file is very large" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; }
    if ( ( not feof ( f ) ) and ferror ( f ) ) {
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка чтения файла \"%s\" \n" :
        "Error reading file \"%s\" \n" ) , argv  [ argj  ] ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( char const (  * ) [ ] ) & u8"Ошибка чтения файла" :
        ( char const (  * ) [ ] ) & "Error reading file" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; }

  char * psw_uni ;
  if ( ns_shifr . use_version == 4 ) 
    psw_uni = password_letters ;
  else
    psw_uni = password_letters6 ;
  psw_uni [ nr ] = '\00' ;

      if ( password_alphabet == 95 )  {
        for ( size_t i  = 0 ; i < nr  ; ++  i )
          if (  psw_uni [ i ] < ' ' or psw_uni  [ i ] > '~' ) {
            psw_uni [ i ] = '\00' ;
            nr = i ;
            break ; } }
        else {
          for ( size_t i  = 0 ; i < nr  ; ++  i )
            if (  ( psw_uni [ i ] < '0' or psw_uni  [ i ] > '9' ) and
                ( psw_uni [ i ] < 'a' or psw_uni  [ i ] > 'z' ) and
                ( psw_uni [ i ] < 'A' or psw_uni  [ i ] > 'Z' ) ) {
              psw_uni [ i ] = '\00' ;
              nr = i ;
              break ; } }
    switch ( ns_shifr . use_version ) {
    case 4 :
      if ( password_alphabet == 95 )
        string_to_password_uni ( & password_letters ,
          & ns_shifr . raspr4  . password_const ,
          & ns_shifr . letters ,  letters_count ) ;
      else
        string_to_password_uni ( & password_letters ,
          & ns_shifr . raspr4  . password_const ,
          & ns_shifr . letters2 , letters_count2 ) ;
      break ;
    case 6 : {
      if ( password_alphabet == 95 )
        string_to_password6_uni ( & password_letters6 ,
          & ns_shifr . raspr6  . password_const ,
          & ns_shifr . letters ,  letters_count ) ;
      else
        string_to_password6_uni ( & password_letters6 ,
          & ns_shifr . raspr6  . password_const ,
          & ns_shifr . letters2 , letters_count2 ) ; }
      break ;
    default :
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"версия %d не поддерживается\n" :
        "version %d is not supported" ) , ns_shifr . use_version )  ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"версия не поддерживается" :
        (char const (*)[]) & "version is not supported" ) ;
      longjmp(ns_shifr  . jump,1); }
    if ( fclose  ( f ) )  {
      int e = errno ; 
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка закрытия файла \"%s\" : %s\n" :
        "Error closing file \"%s\" : %s\n" ) , argv  [ argj  ] ,
            strerror  ( e ) ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( char const (  * ) [ ] ) & u8"Ошибка закрытия файла" :
        ( char const (  * ) [ ] ) & "Error closing file" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; }
    flagpasswd  = true  ; 
    flagreadpasswdfromfile = false  ; }
    else
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
      fprintf  ( stderr,(ns_shifr . localerus ?
        u8"из строки во внутренний пароль = %lx\n" :
        "from string to internal password = %lx\n" ) ,
        ns_shifr . raspr4  . password_const ) ;
# endif                           
        }
      if ( ns_shifr . use_version == 6 ) {
        if ( password_alphabet == 95 )
          string_to_password6_uni ( (char(*)[])(argv[argj]) ,
            & ns_shifr . raspr6  . password_const , & ns_shifr . letters ,
            letters_count ) ;
        else
          string_to_password6_uni ( (char(*)[])(argv[argj]) ,
            & ns_shifr . raspr6  . password_const , & ns_shifr . letters2 ,
            letters_count2 ) ; 
# ifdef SHIFR_DEBUG                           
        { t_number320 password6 ;
          if ( password_alphabet == 95 )
            string_to_password6_uni ( (char(*)[])(argv[argj]) , & password6 ,
              & ns_shifr . letters , letters_count ) ; 
          else
            string_to_password6_uni ( (char(*)[])(argv[argj]) , & password6 ,
              & ns_shifr . letters2 , letters_count2 ) ; 

          fprintf  ( stderr,( ns_shifr . localerus ?
            u8"из строки во внутренний пароль = [ %lx , %lx , %lx , %lx , %lx ]\n"  :
            "from string to internal password = [ %lx , %lx , %lx , %lx , %lx ]\n"  ) ,
          password6 . a [ 4 ] , password6 . a [ 3 ] , password6 . a [ 2 ] ,
          password6 . a [ 1 ] , password6 . a [ 0 ] ) ; }
# endif            
      }
      char  password_letters [ 20 ] ;
      char  password_letters6 [ 100 ] ;
      if ( ns_shifr . use_version == 4 ) {
        if ( password_alphabet == 95 )
          password_to_string_uni ( ns_shifr . raspr4  . password_const ,
            & password_letters , & ns_shifr . letters , letters_count ) ;
        else
          password_to_string_uni ( ns_shifr . raspr4  . password_const ,
            & password_letters , & ns_shifr . letters2 , letters_count2 ) ; }
      if ( ns_shifr . use_version == 6 ) {
        if ( password_alphabet == 95 )
          password_to_string6_uni ( & ns_shifr . raspr6  . password_const ,
            & password_letters6 , & ns_shifr . letters , letters_count ) ;
        else
          password_to_string6_uni ( & ns_shifr . raspr6  . password_const ,
            & password_letters6 , & ns_shifr . letters2 , letters_count2 ) ; }
# ifdef SHIFR_DEBUG
      if ( ns_shifr . use_version == 6 ) {
        if  ( strcmp ( password_letters6 , argv  [ argj  ] ) )  
          fprintf  ( stderr , ns_shifr . localerus ?
            u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
            "Warning! Password \'%s\' is very large. Same as \'%s\'\n"
            , argv  [ argj  ] , & ( password_letters6  [ 0 ] ) ) ; }
      else {
        if  ( strcmp ( password_letters , argv  [ argj  ] ) )  
          fprintf  ( stderr , ns_shifr . localerus ?
            u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
            "Warning! Password \'%s\' is very large. Same as \'%s\'\n"
            , argv  [ argj  ] , & ( password_letters  [ 0 ] ) ) ; }
# endif
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
        if (( strcmp ( argv[argj] , u8"--пар" ) ==  0 )or
          ( strcmp ( argv[argj] , "--pas" ) ==  0 )) { 
          flagreadpasswd  = true  ; }
        else
        if (( strcmp ( argv[argj] , u8"--пар-путь" ) ==  0 )or
          ( strcmp ( argv[argj] , "--pas-path" ) ==  0 )) { 
          flagreadpasswdfromfile  = true  ; }
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
          ns_shifr  . flagtext = true  ; }
        else
        if ( strcmp ( argv[argj] , u8"--4" ) ==  0 ){ 
          ns_shifr . use_version = 4 ; }
        else
        if ( strcmp ( argv  [ argj  ] , u8"--6" ) ==  0 ) { 
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
      shifr_password_generate4 ( ) ;
      break ;
    case 6 :
      shifr_password_generate6 ( ) ;
      break ;
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
    fprintf  ( stderr,( ns_shifr . localerus ? u8"внутренний пароль = %lx\n" :
      "internal password = %lx\n") , ns_shifr . raspr4  . password_const  ) ;
    break ;
  case  6 :
    fputs ( ns_shifr . localerus ? u8"внутренний пароль = [ "  :
      "inner password = [ " , stderr ) ;
    for ( uint64_t const * i = & (  ns_shifr . raspr6  . password_const . a [ 5 ] ) ;
      i not_eq & ( ns_shifr . raspr6  . password_const . a [ 0 ] ) ;  ) {
      --  i ;
      fprintf (stderr, "%lx , " , * i ) ;  }
    fputs  ( "]\n" ,stderr) ;
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
    char  password_letters61 [ 100 ] ;
    char  password_letters62 [ 100 ] ;
    switch  ( ns_shifr . use_version )  {
    case  4 :
      { password_to_string_uni ( ns_shifr . raspr4  . password_const ,
          & password_letters , & ns_shifr . letters , letters_count ) ;
        password_to_string_uni ( ns_shifr . raspr4  . password_const ,
          & password_letters2 , & ns_shifr . letters2 , letters_count2 ) ; }
      break ;
    case  6 :
      { password_to_string6_uni ( & ns_shifr . raspr6  . password_const ,
          & password_letters61 , & ns_shifr . letters , letters_count ) ;
        password_to_string6_uni ( & ns_shifr . raspr6  . password_const ,
          & password_letters62 , & ns_shifr . letters2 , letters_count2 ) ; }
      break ;
    default :
      fprintf ( stderr , ( ns_shifr . localerus ?
        u8"неопознанная версия : \'%d\'\n" :
        "unrecognized version : \'%d\'\n" ) , ns_shifr . use_version ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( char const (  * ) [ ] ) & u8"неопознанная версия" :
        ( char const (  * ) [ ] ) & "unrecognized version" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; }
# ifdef SHIFR_DEBUG        
    printf  ( ( ns_shifr . localerus ? u8"--a95\tбуквами между кавычек = \'%s\'\n" : 
      "--a95\tby letters between quotes = \'%s\'\n"  ) ,
      & ( ( ( ns_shifr . use_version == 6 ) ? password_letters61 :
        password_letters ) [ 0 ] ) ) ;
    printf  ( ( ns_shifr . localerus ?
      u8"--a62\tбуквами между кавычек = \'%s\' (по-умолчанию)\n" : 
      "--a62\tby letters between quotes = \'%s\' (by default)\n"  ) ,
      & ( ( ( ns_shifr . use_version == 6 ) ? password_letters62 :
        password_letters2 )  [ 0 ] ) ) ;
    switch  ( ns_shifr . use_version ) {
    case  4 :
      { uint64_t password2 ;
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
      break ;
    case  6 :
      { t_number320 password6 ;
        string_to_password6_uni ( & password_letters61 , & password6 ,
          & ns_shifr . letters , letters_count ) ; 
      printf  ( ( ns_shifr . localerus ?
          u8"из строки95 во внутренний пароль = [ %lx , %lx , %lx , %lx , %lx ]\n"  :
          "from string95 to internal password = [ %lx , %lx , %lx , %lx , %lx ]\n" ) ,
        password6 . a [ 4 ] , password6 . a [ 3 ] , password6 . a [ 2 ] , 
        password6 . a [ 1 ] , password6 . a [ 0 ] ) ;
        string_to_password6_uni ( & password_letters62 , & password6 ,
          & ns_shifr . letters2 , letters_count2 ) ; 
      printf  ( ( ns_shifr . localerus ?
          u8"из строки62 во внутренний пароль = [ %lx , %lx , %lx , %lx , %lx ]\n"  :
          "from string62 to internal password = [ %lx , %lx , %lx , %lx , %lx ]\n" ) ,
        password6 . a [ 4 ] , password6 . a [ 3 ] , password6 . a [ 2 ] , 
        password6 . a [ 1 ] , password6 . a [ 0 ] ) ;   }
      break ;
    default :
      fprintf ( stderr  , ns_shifr . localerus ?
        u8"неизвестная версия %d\n" : "unknown version %d\n"  ,
        ns_shifr . use_version ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[])& u8"неизвестная версия" :
        (char const (*)[])& "unknown version" ) ;
      longjmp(ns_shifr  . jump,1); }
# else
  if ( password_alphabet == 95 )
    puts  ( & ( ( ( ns_shifr . use_version == 6 ) ?
      password_letters61 : password_letters ) [ 0 ] ) ) ;
  else
    puts  ( & ( ( ( ns_shifr . use_version == 6 ) ? password_letters62 :
      password_letters2 ) [ 0 ] ) ) ;
# endif    
    if ( not flagoutputtofile ) return  0 ;  }
# ifdef SHIFR_DEBUG        
  if  ( flagenc and flagdec ) {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      (char const (*)[])& u8"так зашифровывать или расшифровывать ?" :
      (char const (*)[])& "so encrypt or decrypt ?" ) ;
    longjmp(ns_shifr  . jump,1); }
# endif
  //  по-умолчанию шифруем
  if ( not flagdec  ) flagenc = true  ;
  if ( not flagpasswd )    {
    fputs ( ( ns_shifr . localerus ? u8"введите пароль = " :
      "enter the password = " ) , stdout  ) ;
    switch ( ns_shifr . use_version ) {
    case  6 :
      enter_password6  ( password_alphabet ) ;
      break ;
    case 4 :
      enter_password4  ( password_alphabet ) ;
      break ;
    default :
      fprintf(stderr,( ns_shifr . localerus ?
        u8"Неизвестная версия %d\n" :
        "Unknown version %d\n" ),ns_shifr . use_version);
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"Неизвестная версия" :
        (char const (*)[]) & "Unknown version" ) ;
      longjmp(ns_shifr  . jump,1); } }
  if ( flaginputfromfile ) {
    FILE * const f = fopen  ( & ( ( * inputfilename ) [ 0 ] ) , & ( "r" [ 0 ] ) ) ;
    if  ( f == NULL ) {
      int const e = errno ; 
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка чтения файла \"%s\" : %s\n" :
        "Error reading file \"%s\" : %s\n" ) , & ( ( * inputfilename ) [ 0 ] ) ,
            strerror  ( e ) ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"Ошибка чтения файла" :
        (char const (*)[]) & "Error reading file" ) ;
      longjmp(ns_shifr  . jump,1); }
    flagclosefilefrom = true ;
    ns_shifr  . filefrom = f ;    }
  if ( flagoutputtofile ) {
    FILE * const f = fopen  ( & ( ( * outputfilename  ) [ 0 ] ) , & ( "w" [ 0 ] ) ) ;
    if  ( f == NULL ) {
      int const e = errno ; 
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка записи файла \"%s\" : %s\n" :
        "Error writing file \"%s\" : %s\n"  ) , & ( ( * outputfilename  ) [ 0 ] ) ,
        strerror  ( e ) ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"Ошибка записи файла" :
        (char const (*)[]) & "Error writing file" ) ;
      longjmp(ns_shifr  . jump,1); }
    flagclosefileto = true ;
    ns_shifr  . fileto  = f ;    }
  streambuf_init  ( & shifr_filebuffrom , ns_shifr  . filefrom )  ;
  streambuf_init  ( & shifr_filebufto , ns_shifr  . fileto )  ;
    switch ( ns_shifr . use_version )  {
    case 4 :
      password_load ( ns_shifr . raspr4  . password_const  , & ns_shifr  . shifr , & ns_shifr  . deshi ) ;
      break ;
    case 6 :
      password_load6 ( & ns_shifr . raspr6  . password_const  , & ns_shifr  . shifr6 , 
        & ns_shifr  . deshi6 ) ;
      break ;
    default :
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"версия %d не поддерживается\n" :
        "version %d is not supported" ) , ns_shifr . use_version )  ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"версия не поддерживается" :
        (char const (*)[]) & "version is not supported" ) ;
      longjmp(ns_shifr  . jump,1); }
# ifdef SHIFR_DEBUG    
  if ( ns_shifr . use_version == 6 )  { 
    printarr  ( & "shifr" , & ns_shifr . shifr6 , shifr_deshi_size6 ,stderr) ;
    printarr  ( & "deshi" , & ns_shifr . deshi6 , shifr_deshi_size6 ,stderr) ;  }
  else  {
    printarr  ( & "shifr" , & ns_shifr . shifr , shifr_deshi_size2 ,stderr) ;
    printarr  ( & "deshi" , & ns_shifr . deshi , shifr_deshi_size2 ,stderr) ; }
# endif
  if ( flagenc ) {
    if ( ns_shifr . use_version == 4 ) shifr_encode4 ( ) ;
    else
    if ( ns_shifr . use_version == 6 ) shifr_encode6 ( ) ; }
  else  {
    if ( ns_shifr . use_version == 4 ) shifr_decode4 ( ) ;
    else
    if ( ns_shifr . use_version == 6 ) shifr_decode6 ( ) ; }
  int resulterror  = 0 ;
  if ( flagclosefileto  ) {
    if  ( fclose  ( ns_shifr  . fileto  ) ) {
      int const e = errno ;
      fprintf  (  stderr, ( ns_shifr . localerus ?
        u8"Ошибка закрытия файла записи \"%s\" : %s\n" :
        "Error closing file to writing \"%s\" : %s\n" ) ,
        & ( ( * outputfilename ) [ 0 ] ) , strerror  ( e ) ) ;
      resulterror = 1 ; } }
  if ( flagclosefilefrom ) {
    if  ( ( not feof ( ns_shifr  . filefrom ) ) and fclose  ( ns_shifr  . filefrom ) ) {
      int const e = errno ; 
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка закрытия файла чтения \"%s\" : %s\n" :
        "Error closing file of reading \"%s\" : %s\n"),
        &((*inputfilename)[0]),strerror(e));
      resulterror = 2 ; } }
  return  resulterror ; }
