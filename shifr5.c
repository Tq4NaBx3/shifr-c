// Version 4

// gcc-8 -Wall -std=c11 -Os shifr5.c -o shifr5
// gcc-8 -Wall -std=c11 -Os shifr5.c -o shifr5 && ./shifr5

// 2 бита соль
// 2 бита инфа
// итого 4 бита
// таблица шифра личные 2 бита <-- 4 бита шифрованные
// личные данные b00 => могут быть зашифрованы набором 2^2 = 4шт из 
// b0000 ... b1111 2^4 = 4*4 = 16 штук
// разные расклады шифрования для данных
// b00 = ℂ(4,4*4) = 16*15*14*13/2/3/4 = 1820
// b01 = ℂ(4,4*3) = 12*11*10*9/2/3/4 = 495
// b10 = ℂ(4,4*2) = 8*7*6*5/2/3/4 = 70
// b11 = ℂ(4,4) = 4*3*2*1/2/3/4 = 1
// разные расклады шифрования = b00 * b01 * b10 * b11 =
//  = (4*4)! / ((4!)^4) = 63063000 = (4 ^ 2)! / (((2 ^ 2)!)^(2 ^ 2))
// минимум можно записать с помощью log(2,63063000) ≈ 25.91 бит < 4 байт
// пароль будет 26 бит
// ascii буквы 126-32+1 = 95 шт
// длина буквенного пароля : log ( 95 , 63063000 ) ≈ 3.944 буквы < 4 буквы
// память = 2385 байт = 2.329 KB
// 63063000 = 00011011110000100100001111 реверсивно от слабых к главному 26 бит
// 63063000 * 32 = 2018016000 = 0000000011011110000100100001111 = 0x78487b00
// RAND_MAX размер 31 бит

/*
Связь паролей с идентификацией какой код какому набору биту принадлежит.
Пароль % 1820 даёт код битовых наборов для буквы b00.
C(4,16)=1820=C(3,15)+C(3,14)+...+C(3,3)=455+364+286+220+165+120+84+56+35+20+10+4+1
x<455 первый код 0000 , 455<=x<455+364 первый код 0001 , ...
x=1819 первый код 1101 , второй 1110 , третий 1111
Дальше [пароль/1820] % 495 даёт код для буквы b01.
C(4,12)=495=C(3,11)+C(3,10)+...+C(3,3)=165+120+84+56+35+20+10+4+1
нумерация кодов уже не по порядку, а с исключением занятых кодов буквой b00.
?
Как без огромного массива C(8,64) занятых номеров всё следить ?
 */

// Version 5

// 2 бита соль
// 3 бита инфа
// итого 5 бит
// таблица шифра личные 3 бита <-- 5 бит шифрованные
// личные данные b000 => могут быть зашифрованы набором 2^2 = 4шт из 
// b00000 ... b11111 2^5 = 8*4 = 32 штук
// разные расклады шифрования для данных
// b000 = ℂ(4,4*8) = 32*31*30*29/2/3/4 = 35960
// b001 = ℂ(4,4*7) = 28*27*26*25/2/3/4 = 20475
// b010 = ℂ(4,4*6) = 24*23*22*21/2/3/4 = 10626
// b011 = ℂ(4,4*5) = 20*19*18*17/2/3/4 = 4845
// b100 = ℂ(4,4*4) = 16*15*14*13/2/3/4 = 1820
// b101 = ℂ(4,4*3) = 12*11*10*9/2/3/4 = 495
// b110 = ℂ(4,4*2) = 8*7*6*5/2/3/4 = 70
// b111 = ℂ(4,4*1) = 4*3*2*1/2/3/4 = 1
// разные расклады шифрования = b000 * b001 * b010 * b011 * b100 * b101 * b110 * b111 =
//  = (4*8)! / ((4!)^8) = 239046182973388791e7 ≈ 2.39*(10^24)
// минимум можно записать с помощью log(2,2.39*(10^24)) ≈ 80.98 бит < 11 байт
// пароль будет 81 бит
// ascii буквы 126-32+1 = 95 шт
// длина буквенного пароля : log ( 95 , 2.39*(10^24) ) ≈ 12.33 букв < 13 букв
// три рандома по 31 бит = 93 бит, сдвигаем побитно на 12 бит назад. Получаем 81 бит.
// проверяем, не превысилили ли максимум, (делаем всё заново если-что).
// 2.39*(10^24) / (2^64) = 129587
// 2.39*(10^24) % (2^64) = 3605454088244737408
// 3605454088244737408 / (2^32) = 839460196
// 3605454088244737408 % (2^32) = 130987392
// максимальное число = [ 129587 , 839460196 , 130987392 ] ( строго меньше < )

// Version 6 ?

// 3 бита соль
// 3 бита инфа
// итого 6 бит
// таблица шифра личные 3 бита <-- 6 бит шифрованные
// личные данные b000 => могут быть зашифрованы набором 2^3 = 8шт из 
// b000000 ... b111111 2^6 = 8*8 = 64 штук
// разные расклады шифрования для данных
// b000 = ℂ(8,8*8) = 64*63*62*61*60*59*58*57/2/3/4/5/6/7/8 = 4426165368
// b001 = ℂ(8,8*7) = 56*55*54*53*52*51*50*49/2/3/4/5/6/7/8 = 1420494075
// b010 = ℂ(8,8*6) = 48*47*46*45*44*43*42*41/2/3/4/5/6/7/8 = 377348994
// b011 = ℂ(8,8*5) = 40*39*38*37*36*35*34*33/2/3/4/5/6/7/8 = 76904685
// b100 = ℂ(8,8*4) = 32*31*30*29*28*27*26*25/2/3/4/5/6/7/8 = 10518300
// b101 = ℂ(8,8*3) = 24*23*22*21*20*19*18*17/2/3/4/5/6/7/8 = 735471
// b110 = ℂ(8,8*2) = 16*15*14*13*12*11*10*9/2/3/4/5/6/7/8 = 12870
// b111 = ℂ(8,8) = 8*7*6*5*4*3*2*1/2/3/4/5/6/7/8 = 1
// разные расклады шифрования = b000 * b001 * b010 * b011 * b100 * b101 * b110 * b111 =
//  = (8*8)! / ((8!)^8) ≈ 1.817*(10^52) = (4 ^ 3)! / (((2 ^ 3)!)^(2 ^ 3))
// минимум можно записать с помощью log(2,1.817*(10^52)) ≈ 173.6 бит < 22 байта
// пароль будет 174 бита
// ascii буквы 126-32+1 = 95 шт
// длина буквенного пароля : log ( 95 , 1.817*(10^52) ) ≈ 26.42 букв < 27 букв
// память = 5.879 GB

// в 8 версии бит будет 976 бит 148.6 букв ? память ?
// в 10 версии 5004 бит 761.6 букв ? память ?
// в 12 24307 бит 3700 букв ? память ?

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

# ifdef SHIFR_DEBUG
static  unsigned  long  int fact  ( unsigned  long  int x ) {
  if  ( x ==  0 ) return  0 ;
  unsigned  long  int res = x ;
  do {
    --  x ;
    if ( x <= 1UL ) return res ;
    res *=  x ;
  } while ( true ) ; }
# endif

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
  fputs ( u8"]\n" , stdout  ) ; }
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
# define  raspr4_16_size (UINT16_C(1820))
# define  raspr4_12_size (UINT16_C(495))
# define  raspr4_8_size (UINT8_C(70))
# define  raspr4_4_size (UINT8_C(1))
/*
# define  raspr8_8_size (UINT64_C(4426165368))
# define  raspr8_7_size (UINT32_C(1420494075))
# define  raspr8_6_size (UINT32_C(377348994))
# define  raspr8_5_size (UINT32_C(76904685))
# define  raspr8_4_size (UINT32_C(10518300))
# define  raspr8_3_size (UINT32_C(735471))
# define  raspr8_2_size (UINT16_C(12870))
*/
# define  header_type_size  (UINT8_C(2))

// 0x20 (пробел) ' '    ---     0x7e (тильда) '~'
// 95 шт
# define letters_count (UINT8_C(0x7e - 0x20 + 1))

struct  s_raspr4 {

// массив размеров разных распределений
uint16_t  s [ 4 ] ;
  
// массив указателей на разные распределения
type_raspr_xp ( 4 )  xp  [ 4 ] ;
 
// тип архива бинарного 0x04 + 0x00
unsigned char const headerbyn [ header_type_size ] ;

// "4\n"
unsigned char const headertxt [ header_type_size ] ;

bool  live  ;

uint32_t  password_const  ;

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
 
// тип архива бинарного 0x05 + 0x00
unsigned char const headerbyn [ header_type_size ] ;

// "5\n"
unsigned char const headertxt [ header_type_size ] ;

bool  live  ;

t_number128  password_const  ;

} ;
/*
struct  s_raspr6 {
  
// массив размеров разных распределений
uint64_t  s [ 8 ] ;

// массив указателей на разные распределения
type_raspr_xp ( 8 )  xp  [ 8 ] ;

// тип архива бинарного 0x03 + 0x00
unsigned char const headerbyn [ header_type_size ] ;

// "3\n"
unsigned char const headertxt [ header_type_size ] ;

bool  live  ;

} ;*/

struct  s_ns_shifr  {

// буквы разрешённые в пароле :
char  letters [ letters_count ] ;  
  
bool  localerus ; 

// хранилище дефолтного состояния
struct termios stored_termios  ;

// заголовок архива "shifr" без конца строки
unsigned char const mainheader [ 5 ] ;

// исключения
jmp_buf jump ;
char const (  * string_exception  ) [ ] ;

struct  s_raspr4 raspr4 ;
struct  s_raspr5 raspr5 ;
//struct  s_raspr6 raspr6 ;

int use_version ; //  4 или 5

} ;

static  struct  s_ns_shifr  ns_shifr = {
  .mainheader = { [ 0 ] = 's' , [ 1 ] = 'h' ,
    [ 2 ] = 'i' , [ 3 ] = 'f' , [ 4 ] = 'r' } ,
  .raspr4 = {
    .s = { [ 3 ] = raspr4_16_size , [ 2 ] = raspr4_12_size ,
      [ 1 ] = raspr4_8_size , [ 0 ] = raspr4_4_size } ,
    .headerbyn = { [ 0 ] = 0x04 , [ 1 ] = 0x00 } ,
    .headertxt = { [ 0 ] = '4' , [ 1 ] = '\n' } ,
    .live = false ,
    } ,
  .raspr5 = {
    .s = { [ 7 ] = raspr4_32_size , [ 6 ] = raspr4_28_size ,
      [ 5 ] = raspr4_24_size , [ 4 ] = raspr4_20_size ,
      [ 3 ] = raspr4_16_size , [ 2 ] = raspr4_12_size ,
      [ 1 ] = raspr4_8_size , [ 0 ] = raspr4_4_size } ,
    .headerbyn = { [ 0 ] = 0x05 , [ 1 ] = 0x00 } ,
    .headertxt = { [ 0 ] = '5' , [ 1 ] = '\n' } ,
    .live = false ,
    } ,
  . use_version  = 4 ,
  /*.raspr6 = {
    .s = { [ 7 ] = raspr8_8_size , [ 6 ] = raspr8_7_size ,
      [ 5 ] = raspr8_6_size , [ 4 ] = raspr8_5_size ,
      [ 3 ] = raspr8_4_size , [ 2 ] = raspr8_3_size ,
      [ 1 ] = raspr8_2_size , [ 0 ] = 0 } ,
    .headerbyn = { [ 0 ] = 0x03 , [ 1 ] = 0x00 } ,
    .headertxt = { [ 0 ] = '3' , [ 1 ] = '\n' } ,
    .live = false ,
    } ,*/
} ;

static  void  password_to_string ( uint32_t password , strp const string ) {
  char * stringi = & ( ( * string )  [ 0 ] ) ;
  if ( password ) {
    while ( true ) {
      // здесь предыдущие размеры заняли место паролей
      --  password  ;
      ( * stringi ) = ns_shifr . letters [ password % (uint32_t)letters_count ] ;
      ++  stringi ;
      if ( password < (uint32_t)letters_count ) break ;
      password /= (uint32_t)letters_count ; } }
  ( * stringi ) = '\0' ; }
    
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
  uint32_t number00 = ( ( ((uint32_t)ost) << 16 ) bitor ( number ->  a [ 0 ] bitand 0xffff ) ) ;
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
  
static  void  password_to_string5 (
  t_number128 const * const restrict password0 , strp const string ) {
//fputs("0.",stdout);fflush(stdout);
  char * stringi = & ( ( * string )  [ 0 ] ) ;
  //int index = 0 ;
//fputs("1.",stdout);fflush(stdout);
  if ( number128_not0 ( password0 ) ) {
//fputs("2.",stdout);fflush(stdout);
    t_number128 password = * password0  ;
//fputs("3.",stdout);fflush(stdout);
    do {
//fputs("4.",stdout);fflush(stdout);
//printf("i=%d ",index);fflush(stdout);
      // здесь предыдущие размеры заняли место паролей
      number128dec  ( & password  ) ;
//fputs("5.",stdout);fflush(stdout);
      ( * stringi ) = ns_shifr . letters [ number128_div8mod  ( & password ,
        letters_count ) ] ;
//fputs("6.",stdout);fflush(stdout);
      ++  stringi ;
  //    ++  index ;
//fputs("7.",stdout);fflush(stdout);
    } while ( number128_not0 ( & password ) ) ;
//fputs("8.",stdout);fflush(stdout);
  }
//fputs("9.",stdout);fflush(stdout);
  ( * stringi ) = 0 ;
//fputs("a.",stdout);fflush(stdout);
  }
  
static  void  string_to_password ( strcp const string ,
  uint32_t * const password ) {
  char const * restrict stringi = & ( ( * string )  [ 0 ] ) ;
  if  ( ( * stringi ) == 0 ) {
    ( * password  ) = 0 ;
    return ; }
  uint32_t pass = 0 ;
  uint32_t  mult  = 1 ;
  do  {
    uint8_t i = letters_count ;
    do {
      -- i ;
      if ( ( * stringi ) == ns_shifr . letters  [ i ] ) goto found ; 
    } while ( i ) ;
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      ( char const ( * ) [ ] ) & u8"неправильная буква в пароле" :
      ( char const ( * ) [ ] ) & "wrong letter in password" ) ;
    longjmp(ns_shifr  . jump,1);
found :
    pass  +=  ((uint32_t)(i+1)) * mult ;
    mult  *=  (uint32_t)letters_count ;
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
  np->a [ 0 ] = r0 + ( r1 >> 56 ) ;
  if ( np ->  a [ 0 ] < r0  ) ++  ( np  ->  a [ 1 ] ) ; }  
  
static  void  string_to_password5 ( strcp const string ,
  t_number128 * const restrict password ) {
  char const * restrict stringi = & ( ( * string )  [ 0 ] ) ;
  if  ( ( * stringi ) == 0 ) {
    number128_set0 ( password  ) ;
    return ; }
  t_number128  pass ;
  number128_set0  ( & pass  ) ;
  t_number128  mult = {{ [ 0 ] = 1 , [ 1 ] = 0 }} ;
  do  {
    uint8_t i = letters_count ;
    do {
      -- i ;
      if ( ( * stringi ) == ns_shifr . letters  [ i ] ) goto found ; 
    } while ( i ) ;
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      ( char const ( * ) [ ] ) & u8"неправильная буква в пароле" :
      ( char const ( * ) [ ] ) & "wrong letter in password" ) ;
    longjmp(ns_shifr  . jump,1);
found : ;
    { t_number128  tmp = mult ;
      number128_mul8  ( & tmp , i + 1 ) ;
      number128_add ( &  pass  , & tmp )  ; }
    number128_mul8  ( & mult , letters_count ) ;
    ++  stringi ;
  } while ( * stringi ) ;
  ( * password  ) = pass ; }
  
static  void  shifr_init ( void  ) {
  { char * j = & ( ns_shifr . letters [ 0 ] ) ;
    for ( uint8_t i = 0x20 ; i <= 0x7e ; ++ i , ++ j ) ( * j ) = i ;  } }
    
static  void  raspr4_init ( void  ) {
# ifdef SHIFR_DEBUG
  if ( ns_shifr .  raspr4 . live ) {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      ( char const ( * ) [ ] ) & u8"raspr4_init: двойной вызов конструктора" :
      ( char const ( * ) [ ] ) & "raspr4_init: double constructor call" ) ;
    longjmp ( ns_shifr  . jump  , 1 ) ; }
# endif
  uint8_t raspri  = 4 ;
  do {
    uint8_t const raspri4 = raspri * 4 ;
    --  raspri  ;
    // raspri = 3 , 2 , 1
    // raspri4 = 16 , 12 , 8
    { uint16_t  j = 0 ;
      type_raspr_xp ( 4 ) ap = malloc  ( sizeof (
          uint8_t [ ns_shifr .  raspr4  . s [ raspri ] ] [ 4 ] ) ) ;
//printf(u8"raspri = %d , размер = %d\n",(int)raspri,(int)ns_shifr .  raspr4  . s [ raspri ]);
      ns_shifr  . raspr4  . xp [ raspri ] = ap ;
      // ap - указатели на разные массивы
      for ( uint8_t i0 = 0 ; i0 < ( raspri4 - 3 )  ; ++  i0 )
        for ( uint8_t i1 = i0 + 1 ; i1 < (  raspri4 - 2 )  ; ++  i1 )
          for ( uint8_t i2 = i1 + 1 ; i2 < (  raspri4 - 1 ) ; ++  i2 )
            for ( uint8_t i3 = i2 + 1 ; i3 < raspri4  ; ++  i3 ) {
              ( * ap ) [ j ] [ 0 ] = i0  ;
              ( * ap ) [ j ] [ 1 ] = i1  ;
              ( * ap ) [ j ] [ 2 ] = i2  ;
              ( * ap ) [ j ] [ 3 ] = i3  ; 
              ++  j ; } }
  } while ( raspri > 1 ) ; 
  ns_shifr .  raspr4 . live = true  ; }

static  void  raspr4_show ( void  ) {
# ifdef SHIFR_DEBUG
  if ( not  ns_shifr .  raspr4 . live ) {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      ( char const ( * ) [ ] ) & u8"raspr4_show: распределение не создано" :
      ( char const ( * ) [ ] ) & "raspr4_show: raspr is not created" ) ;
    longjmp ( ns_shifr  . jump  , 1 ) ; }
# endif
  uint8_t raspri  = 4 ;
  do {
    uint8_t const raspri4 = raspri * 4 ;
    --  raspri  ;
    // raspri = 3 , 2 , 1
    // raspri4 = 16 , 12 , 8
    { uint16_t  j = 0 ;
      type_raspr_xp ( 4 ) ap = ns_shifr  . raspr4  . xp [ raspri ]  ;
      // ap - указатели на разные массивы
      for ( uint8_t i0 = 0 ; i0 < ( raspri4 - 3 )  ; ++  i0 )
        for ( uint8_t i1 = i0 + 1 ; i1 < (  raspri4 - 2 )  ; ++  i1 )
          for ( uint8_t i2 = i1 + 1 ; i2 < (  raspri4 - 1 ) ; ++  i2 )
            for ( uint8_t i3 = i2 + 1 ; i3 < raspri4  ; ++  i3 ) {
printf("[%x,%x,%x,%x]",( * ap ) [ j ] [ 0 ],( * ap ) [ j ] [ 1 ],
  ( * ap ) [ j ] [ 2 ],( * ap ) [ j ] [ 3 ]);
              ++  j ; } }
puts("\n");
  } while ( raspri > 1 ) ; }  
  
static  void  raspr5_init ( void  ) {
# ifdef SHIFR_DEBUG
  if ( ns_shifr .  raspr5 . live ) {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      ( char const ( * ) [ ] ) & u8"raspr5_init: двойной вызов конструктора" :
      ( char const ( * ) [ ] ) & "raspr5_init: double constructor call" ) ;
    longjmp ( ns_shifr  . jump  , 1 ) ; }
# endif
  uint8_t raspri  = 8 ;
  do {
    uint8_t const raspri4 = raspri * 4 ;
    --  raspri  ;
    // raspri = 7 , 6 , 5 , 4 , 3 , 2 , 1
    // raspri4 = 32 , 28 , 24 , 20 , 16 , 12 , 8
    { uint16_t  j = 0 ;
      //type_raspr_xp ( 4 ) ap = malloc  ( ns_shifr .  raspr5  . s [ raspri ] ) ;
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
  ns_shifr .  raspr5 . live = true  ; }  
  
static  void  raspr4_destr ( void  ) {
  if ( not  ns_shifr .  raspr4 . live ) return  ;
  uint8_t raspri  = 4 ;
  do {
    --  raspri  ;
    free ( ns_shifr  . raspr4  . xp [ raspri ] ) ;
  } while ( raspri > 1 ) ; }

static  void  raspr5_destr ( void  ) {
  if ( not  ns_shifr .  raspr5 . live ) return  ;
  uint8_t raspri  = 8 ;
  do {
    --  raspri  ;
    free ( ns_shifr  . raspr5  . xp [ raspri ] ) ;
  } while ( raspri > 1 ) ; }
  
static  void  shifr_destr ( void  ) {
  raspr4_destr  ( ) ;
  raspr5_destr  ( ) ; }
  
// пароль раскладываем в таблицу шифровки , дешифровки
  // пароль % 0x10 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  // пароль делим на 16, остаются 15! вариантов пароля
  // пароль % 0xf = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
  // секретных кодов для соли+данных 0x1  
void  password_load ( uint32_t  const password_const  , arrp const shifrp , 
  arrp const deship ) {
  uint8_t const codefree = 0xff ;
  initarr ( shifrp , codefree , shifr_deshi_size2 )  ;
  initarr ( deship , codefree , shifr_deshi_size2 )  ;
  uint32_t password = password_const ;
  uint16_t  cindex4_16  = password  % raspr4_16_size ;
  password  /=  raspr4_16_size  ;
  // 00
  for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
    (*shifrp) [ j ] = ( * ( ns_shifr.raspr4.xp [ 3 ] ) )
       [ cindex4_16 ] [ j ] ;
    (*deship) [ ( * ( ns_shifr.raspr4.xp [ 3 ] ) )
       [ cindex4_16 ] [ j ] ] = 0 ; }
    // 01-10
      for ( uint8_t arr_ind = 1 ; arr_ind <= 2 ; ++ arr_ind ) {
        uint8_t index = 0 ;
        uint16_t  cindex4_i  = password  % ( ns_shifr.raspr4.s [ 3 - arr_ind ] ) ;
        password  /= ( ns_shifr.raspr4.s [ 3 - arr_ind ] ) ;
        { uint8_t old_index = 0xff ;
          for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
            uint8_t new_index = ( * ( ns_shifr.raspr4.xp [ 3 - arr_ind ] ) )
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
            ( * deship  ) [ index ] = arr_ind ;
            ++  index ; } } } //  for arr_ind
      
      // пароль больше не нужен , беру оставшиеся коды
  // 11
      { uint8_t index3 = 0 ;
        for ( uint8_t  i = 0xc  ; i <=  0xf ; ++  i ) {  
          do  {
            if ( (  * deship  ) [ index3 ] == codefree ) break  ;
            ++  index3 ;
          } while ( true  ) ; 
          ( * shifrp  ) [ i ] = index3 ;
          ( * deship  ) [ index3 ] = 3 ;
          ++  index3 ; } } }

// пароль раскладываем в таблицу шифровки , дешифровки
  // пароль % 0x20 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  // пароль делим на 32, остаются 31! вариантов пароля
  // пароль % 0x1f = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
  // секретных кодов для соли+данных 0x1  
void  password_load5 ( t_number128  const * password_constp  , arrp const shifrp , 
  arrp const deship ) {
//fputs("2.",stdout);fflush(stdout);
  uint8_t const codefree = 0xff ;
//fputs("3.",stdout);fflush(stdout);
  initarr ( shifrp , codefree , shifr_deshi_size5 )  ;
//fputs("4.",stdout);fflush(stdout);
  initarr ( deship , codefree , shifr_deshi_size5 )  ;
//fputs("5.",stdout);fflush(stdout);
  t_number128 password = * password_constp ;
//fputs("6.",stdout);fflush(stdout);
  uint16_t  cindex4_32  = number128_div16mod  ( & password  , raspr4_32_size  ) ;
//fputs("7.",stdout);fflush(stdout);
  // 000
  for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
//fputs("8.",stdout);fflush(stdout);    
    ( * shifrp  ) [ j ] = ( * ( ns_shifr.raspr5.xp [ 7 ] ) )
       [ cindex4_32 ] [ j ] ;
//fputs("9.",stdout);fflush(stdout);
    ( * deship  ) [ ( * ( ns_shifr.raspr5.xp [ 7 ] ) )
       [ cindex4_32 ] [ j ] ] = 0 ;
//fputs("a.",stdout);fflush(stdout);
  }
//fputs("b.",stdout);fflush(stdout);
    // 001-110
      for ( uint8_t arr_ind = 1 ; arr_ind <= 6 ; ++ arr_ind ) {
//fputs("c.",stdout);fflush(stdout);
        uint8_t index = 0 ;
//fputs("d.",stdout);fflush(stdout);
        uint16_t  cindex4_i  = number128_div16mod  ( & password  , ns_shifr.raspr5.s [ 7 - arr_ind ]  ) ;
//fputs("e.",stdout);fflush(stdout);
        { uint8_t old_index = 0xff ;
//fputs("f.",stdout);fflush(stdout);
          for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
//fputs("10.",stdout);fflush(stdout);            
            uint8_t new_index = ( * ( ns_shifr.raspr5.xp [ 7 - arr_ind ] ) )
              [ cindex4_i ] [ j ] ;
//fputs("11.",stdout);fflush(stdout);
            { uint8_t passed = old_index + 1 ;
//fputs("12.",stdout);fflush(stdout);              
              do {
                if ( (  * deship  ) [ index ] == codefree ) {
                  if ( passed == new_index ) break ;
                  ++ passed  ; }
                ++  index ;
              } while ( true ) ; }
            old_index = new_index ;
            ( * shifrp  ) [ 0x4 * arr_ind + j ] = index ;
            ( * deship  ) [ index ] = arr_ind ;
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
          ( * deship  ) [ index3 ] = 7 ;
          ++  index3 ; } } }  
  
void datasole ( arrcp const secretdata , arrp const secretdatasole , size_t  data_size ) {
  uint8_t const * id = &((*secretdata)[data_size]) ;
  uint8_t * ids = &((*secretdatasole)[data_size]) ;
  int ran = rand ( )  ;
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 00 => 0000 или 0001 или 0010 или 0011
    // в таблице всё рядом, 4 варианта равномерно распределены
    (* ids) = ((* id)<<2) bitor (ran%4) ;
    ran >>= 2 ;
  } while ( id not_eq &((*secretdata)[0]) ) ; }  
  
static  void  char_to_hex ( char  buf , char ( * const buf2 ) [ 2 ] ) {
  unsigned  char c = buf & 0xf ;
  if ( c >= 0 and c <= 9 ) (*buf2)[0] = '0' + c ;
  else  (*buf2)[0] = 'a' + (c - 10) ;
  c = (buf >> 4) & 0xf ;
  if ( c >= 0 and c <= 9 ) (*buf2)[1] = '0' + c ;
  else  (*buf2)[1] = 'a' + (c - 10) ; }

static  void  hex_to_char ( char const ( * restrict buf2 ) [ 2 ] , char * const restrict buf ) {
  if  ((*buf2)[0] >= '0' and (*buf2)[0] <= '9') (* buf) = (*buf2)[0] - '0';
  else  if((*buf2)[0] >= 'a' and (*buf2)[0] <= 'f') (* buf) = 10 + ((*buf2)[0] - 'a');
  else  {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ? (char const (*)[]) & u8"плохая hex буква" :
      (char const (*)[])& "bad hex letter" ) ;
    longjmp(ns_shifr  . jump,1); }
  if  ((*buf2)[1] >= '0' and (*buf2)[1] <= '9') (* buf) or_eq (((*buf2)[1] - '0')<<4);
  else  if((*buf2)[1] >= 'a' and (*buf2)[1] <= 'f') (* buf) or_eq ((10 + ((*buf2)[1] - 'a'))<<4);
  else  {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ? (char const (*)[]) & u8"плохая hex буква" :
      (char const (*)[]) & "bad hex letter" ) ;
    longjmp(ns_shifr  . jump,1); } }
/*
// разрешать читать, например, символы перевода строки. '\n'
static  bool  isBADhex_to_char ( char const ( * restrict buf2 ) [ 2 ] ,
  char * const restrict buf ) {
  if  ((*buf2)[0] >= '0' and (*buf2)[0] <= '9') (* buf) = (*buf2)[0] - '0';
  else  if((*buf2)[0] >= 'a' and (*buf2)[0] <= 'f')
    (* buf) = 10 + ((*buf2)[0] - 'a');
  else  return  true  ;
  if  ((*buf2)[1] >= '0' and (*buf2)[1] <= '9')
    (* buf) or_eq (((*buf2)[1] - '0')<<4);
  else  if((*buf2)[1] >= 'a' and (*buf2)[1] <= 'f')
    (* buf) or_eq ((10 + ((*buf2)[1] - 'a'))<<4);
  else return true  ; 
  return  false ; }*/
    
// Отключить эхо-вывод и буферизацию ввода
static  void set_keypress (void) {
  if  ( tcgetattr ( 0 , & ns_shifr  . stored_termios  ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifr . localerus ? u8"ошибка чтения tcgetattr : %s\n" :
      "error read tcgetattr : %s\n" ) ,se ) ;
    ns_shifr  . string_exception  = (char const (*)[])se ;
    longjmp(ns_shifr  . jump,1); }

  struct termios new_termios = ns_shifr . stored_termios  ;
  new_termios.c_lflag &= ~(ECHO bitor ICANON);
  new_termios.c_cc[VMIN] = 1;  
  new_termios.c_cc[VTIME] = 0; 
 
  if(tcsetattr(0, TCSANOW, & new_termios)){
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifr . localerus ? u8"ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifr  . string_exception  = (char const (*)[])se ;
    longjmp(ns_shifr  . jump,1); } }
 
// Восстановление дефолтного состояния
static  void reset_keypress (void) {
  if  ( tcsetattr ( 0 , TCSANOW , & ns_shifr . stored_termios ) ) {
    char const * const se = strerror ( errno ) ;
    fprintf ( stderr  , ( ns_shifr . localerus ? u8"ошибка записи tcsetattr : %s\n" :
      "error write tcsetattr : %s\n"  ) , se  ) ;
    ns_shifr  . string_exception  = (char const (*)[]) se ;
    longjmp(ns_shifr  . jump,1); } }  
  
int main  ( int  argc , char * * argv  )  {
  char const * const locale = setlocale ( LC_ALL  , ""  ) ;
  ns_shifr . localerus = ( strcmp  ( locale  , "ru_RU.UTF-8" ) ==  0 ) ;
  int exc = setjmp  ( ns_shifr  . jump  ) ;
  if ( exc ) {
    fprintf ( stderr  , ( ns_shifr . localerus ? u8"Исключение : %s\n" :
      "Exception : %s\n" ) , & ( ( *ns_shifr  . string_exception ) [ 0 ] ) ) ;
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
//puts(u8"-2.");  
  shifr_init  ( ) ;
//puts(u8"-1.");  
  if  ( argc  <=  1  ) {
    puts ( ns_shifr . localerus ?
      u8"Шифр2 ©2019 Глебов А.Н.\nСинтаксис : shifr2 [параметры]" :
      "Shifr2 ©2019 Glebe A.N.\nSyntax : shifr2 [options]" ) ;
    puts  ( ns_shifr . localerus ? u8"Параметры :" : "Options :"  ) ;
    puts  (ns_shifr . localerus ? u8"--ген-пар или\n--gen-pas\tгенерировать пароль" :
      "--gen-pas\tpassword generate" );
    puts  (ns_shifr . localerus ? u8"--зашифр или\n--encrypt\tзашифровать (по-умолчанию)" :
      "--encrypt\t(by default)" );
    puts  (ns_shifr . localerus ? u8"--расшифр или\n--decrypt\tрасшифровать" :
      "--decrypt" );
    puts  (ns_shifr . localerus ? u8"--пароль или\n--pass \"строка_пароля\"\tиспользовать данный пароль" :
      "--pass \"password_string\"\tuse this password" );
    puts  (ns_shifr . localerus ? u8"--вход или\n--input \"имя_файла\"\tчитать из файла" :
    "--input \"file_name\"\tread from file");
    puts  (ns_shifr . localerus ? u8"--выход или\n--output \"имя_файла\"\tзаписывать в файл" :
      "--output \"file_name\"\twrite to file"    );
    puts  (ns_shifr . localerus ?  u8"--текст или\n--text\tшифрованный файл записан текстом ascii" :
      "--text\tencrypted file written in ascii text"    );
    puts  ( ns_shifr . localerus ?  u8"--4\tиспользовать четырёх битное шифрование ( четыре буквы ) ( по-умолчанию )" :
      "--4\tusing four bit encryption ( four letters ) ( by default )" ) ;
    puts  ( ns_shifr . localerus ?  u8"--5\tиспользовать пяти битное шифрование ( ? буквы )" :
      "--5\tusing five bit encryption ( ? letters )" ) ;
    puts  (ns_shifr . localerus ?  u8"Длина пароля, дающая разное шифрование = 4 буквы. Бо\u0301льшая длина будет действовать, как другой пароль с меньшей длиной." :
      "Password length giving different encryption = 4 letters. A longer length will act like another password with a shorter length." ) ;
    fputs  ( ns_shifr . localerus ?  u8"Буквы в пароле : \"" : "Letters in password : \"" , stdout ) ;
    
    for ( char const * cj = & ( ns_shifr  . letters [ 0 ] ) ;
      cj not_eq ( & ( ns_shifr  . letters [ letters_count ] ) ) ; ++ cj )
      fputc ( * cj  , stdout  ) ;
    fputs ( "\"\n"  , stdout  ) ;
    shifr_destr ( ) ;
    return 0 ; }
# if  RAND_MAX  !=  0x7fffffff
# error RAND_MAX  !=  0x7fffffff
# endif
  // 31 бит
  srand ( time  ( 0 ) ) ;
  raspr4_init ( ) ;
//puts("-1.");  
  raspr5_init ( ) ;
//puts("0.");
/*fputs("распределение=",stdout);
  raspr4_show ( ) ;
puts("");*/
  for ( int argj = 1 ; argv [ argj ] ; ++ argj ) {
    if  ( flagreadpasswd  ) {
      if  ( flagpasswd  ) {
        ns_shifr  . string_exception  = ( ns_shifr . localerus ?
          (char const (*)[]) & u8"пароль уже задан" :
          (char const (*)[]) & "password already set" );
        longjmp(ns_shifr  . jump,1); }
      if ( ns_shifr . use_version == 4 ) {
        string_to_password ( (char(*)[])(argv[argj]) ,
                           & ns_shifr . raspr4  . password_const ) ; 
# ifdef SHIFR_DEBUG
      printf  ( (ns_shifr . localerus ? u8"из строки во внутренний пароль = %x\n" :
        "from string to internal password = %x\n" ) , ns_shifr . raspr4  . password_const ) ;
# endif                           
        }
      else {
        string_to_password5 ( (char(*)[])(argv[argj]) ,
                           & ns_shifr . raspr5  . password_const ) ; 
# ifdef SHIFR_DEBUG                           
{ t_number128 password5 ;
      string_to_password5 ( (char(*)[])(argv[argj]) , & password5 ) ; 

      printf((ns_shifr . localerus ? u8"из строки во внутренний пароль = [%lx,%lx]\n":"from string to internal password = [%lx,%lx]\n"),password5.a[1],password5.a[0]) ;
      

    }
# endif    
        
      }
        
      char  password_letters [ 20 ] ;
        
      if ( ns_shifr . use_version == 4 )
        password_to_string ( ns_shifr . raspr4  . password_const ,
          & password_letters ) ;
      else{
        password_to_string5 ( & ns_shifr . raspr5  . password_const ,
          & password_letters ) ;
      }
   
// Сделать предупреждение, что пароли равны :
// "$WSh" == "" : 63063000 == 0
        
        if  ( strcmp ( password_letters , argv[argj] ) )  
          fprintf  ( stderr , ns_shifr . localerus ?
            u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
            "Warning! Password \'%s\' is very large. Same as \'%s\'\n"
            ,argv[argj],&(password_letters[0])); 
        
        flagpasswd  = true  ;
        flagreadpasswd = false; }
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
        else
        if (( strcmp ( argv[argj] , u8"--вход" ) ==  0 )or
          ( strcmp ( argv[argj] , u8"--input" ) ==  0 )) { 
          flagreadinput  = true  ; }
        else
        if (( strcmp ( argv[argj] , u8"--выход" ) ==  0 ) or
          ( strcmp ( argv[argj] , u8"--output" ) ==  0 )){ 
          flagreadoutput  = true  ; }  
        else
        if (( strcmp ( argv[argj] , u8"--текст" ) ==  0 ) or
          ( strcmp ( argv[argj] , u8"--text" ) ==  0 )){ 
          flagtext = true  ; }
        else
        if (( strcmp ( argv[argj] , u8"--4" ) ==  0 ) or
          ( strcmp ( argv[argj] , u8"--4" ) ==  0 )){ 
          //raspr4_init ( ) ;
          ns_shifr . use_version = 4 ; }
        else
        if (( strcmp ( argv[argj] , u8"--5" ) ==  0 ) or
          ( strcmp ( argv[argj] , u8"--5" ) ==  0 )){ 
          //raspr5_init ( ) ;
          ns_shifr . use_version = 5 ; }  
        else {
          fprintf ( stderr , ( ns_shifr . localerus ?
            u8"неопознанная опция : \'%s\'\n" :
            "unrecognized option : \'%s\'\n" ) , argv [ argj ] ) ;
          ns_shifr  . string_exception  = ( ns_shifr . localerus ?
            (char const (*)[])& u8"неопознанная опция" :
            (char const (*)[])& u8"unrecognized option" ) ;
          longjmp(ns_shifr  . jump,1); } } }
  if ( flaggenpasswd ) {
    srand ( time  ( 0 ) ) ;
    if ( ns_shifr . use_version == 4 ) {
      int r ;
      // цикл для равномерного рандома
      do {
        r = rand  ( ) ;
      } while ( r >= ( 63063000 * 34 ) ) ;
      ns_shifr . raspr4  . password_const = r / 34 ; }
    else {
      t_number96 ro0 ;
      t_number96 ro ;      
/*
 сверху 1 бит всегда ноль,
 снизу 4 бита у всех рандомов округляю
  [1 17 10 4 ]   [1 22 5 4 ]   [1 27 4] 
       |     |       |     |     |   
     [ 17 ]     [ 10 22 ]   [ 5 27]
  в сумме 17+32+32=81 бит   
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
randok : ns_shifr . raspr5  . password_const = (t_number128){{[1]=ro.a[2],
  [0]=(((uint64_t)(ro.a[1]))<<32)bitor((uint64_t)(ro.a[0]))}} ;
printf((ns_shifr . localerus ? u8"пароль5=[%x,%x,%x]\n":"password5=[%x,%x,%x]\n"),ro.a[2],ro.a[1],ro.a[0]) ;
//printf(u8"пароль5=[%lu,%lu]\n",ns_shifr . raspr5  . password_const.a[1],ns_shifr . raspr5  . password_const.a[0]) ;
      }
      
    flagpasswd  = true  ;
# ifdef SHIFR_DEBUG    
    if ( ns_shifr . use_version == 4 )
      printf((ns_shifr . localerus ? u8"внутренний пароль = %x\n" :
        "internal password = %x\n") ,ns_shifr . raspr4  . password_const  ) ;
    else
      printf((ns_shifr . localerus ? u8"внутренний пароль = [%lx,%lx]\n":"inner password = [%lx,%lx]\n"),ns_shifr . raspr5  . password_const.a[1],ns_shifr . raspr5  . password_const.a[0]) ;
# endif    
    char  password_letters [ 20 ] ;
    if ( ns_shifr . use_version == 4 )
      password_to_string ( ns_shifr . raspr4  . password_const , & password_letters ) ;
    else
      password_to_string5 ( & ns_shifr . raspr5  . password_const , & password_letters ) ;
    printf((ns_shifr . localerus ? u8"пароль буквами = \'%s\'\n" : 
      "password by letters = \'%s\'\n"),&(password_letters[0]));
    if ( ns_shifr . use_version == 4 )
    { uint32_t password2 ;
      string_to_password ( & password_letters , & password2 ) ; 
# ifdef SHIFR_DEBUG
      printf  ( (ns_shifr . localerus ? u8"из строки во внутренний пароль = %x\n" :
        "from string to internal password = %x\n" ) , password2 ) ;
# endif
    }
    else  { t_number128 password5 ;
      string_to_password5 ( & password_letters , & password5 ) ; 
# ifdef SHIFR_DEBUG
      printf((ns_shifr . localerus ? u8"из строки во внутренний пароль = [%lx,%lx]\n":"from string to internal password = [%lx,%lx]\n"),ns_shifr . raspr5  . password_const.a[1],ns_shifr . raspr5  . password_const.a[0]) ;
      
# endif
    }
    if ( not flagoutputtofile ) {
      puts  ( ns_shifr . localerus ?
        u8"Шифрование не произведено. Используйте опцию заданием выходного файла или с опцией --пароль предлагаемого пароля." :
        "No encryption. Use the option to specify the output file or the option --pass of the proposed password." ) ; 
      return  0 ; } }
  if  ( flagenc and flagdec ) {
    ns_shifr  . string_exception  = ( ns_shifr . localerus ?
      (char const (*)[])& u8"так зашифровывать или расшифровывать ?" :
      (char const (*)[])& u8"so encrypt or decrypt ?" ) ;
    longjmp(ns_shifr  . jump,1); }
  //  по-умолчанию шифруем
  if ( not flagdec  ) flagenc = true  ;
  if ( not flagpasswd )    {
    char p [ 26 ] ;
    fputs ( ( ns_shifr . localerus ? u8"введите пароль = " :
      "enter the password = " ) , stdout  ) ;
    set_keypress  ( ) ;
    char ( * res ) [ 26 ] = ( char ( * ) [ 26 ] )
      fgets ( & ( p [ 0 ] ) , 26 , stdin ) ;
    reset_keypress ( ) ;
    char * j = &((*res)[0]) ;
    while ( ( ( * j ) not_eq '\n' ) and ( ( * j ) not_eq '\0' ) and
      ( j < ( & ( * res ) [ 26 ] ) ) ) ++ j ;
    if ( j < ( & ( ( * res ) [ 26 ] ) ) ) ( * j ) = '\0' ;
    else  {
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"в пароле нет конца строки" :
        (char const (*)[]) & "there is no end of line in the password" ) ;
      longjmp(ns_shifr  . jump,1); }
    if ( ns_shifr . use_version == 4 )
      string_to_password ( res , & ns_shifr . raspr4  . password_const ) ;
    else { 
      string_to_password5 ( res , & ns_shifr . raspr5  . password_const ) ; 
    }
  }
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
//printf("filefrom = %p\n",filefrom);        
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
/*printf("filefrom = %p = [ ",filefrom);            
for ( uint8_t const * i = ( uint8_t const * ) filefrom  ;
  i < ( uint8_t const * const ) ( filefrom  + 1 ) ; ++  i )
  printf("%x , ",(unsigned int)(*i));
puts("]");                
printf("fileto = %p = [ ",fileto);            
for ( uint8_t const * i = ( uint8_t const * ) fileto ;
  i < ( uint8_t const * const ) ( fileto + 1 ) ; ++  i )
  printf("%x , ",(unsigned int)(*i));
puts("]");            */
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
//puts("0.");    
    if ( ns_shifr . use_version == 4 )  
      password_load ( ns_shifr . raspr4  . password_const  , & shifr , & deshi ) ;
    else
      password_load5 ( & ns_shifr . raspr5  . password_const  , & shifr , & deshi ) ;
//puts("1.");  
  printarr  ( & "shifr" , & shifr , shifr_deshi_size5 ) ;
  printarr  ( & "deshi" , & deshi , shifr_deshi_size5 ) ;

  if ( flagenc ) {
    // главный заголовок "шифр" без конца строки
    size_t writecount = fwrite ( & ns_shifr . mainheader  , 1 ,
      sizeof ( ns_shifr . mainheader ) , fileto ) ;
    if ( writecount < sizeof ( ns_shifr . mainheader ) ) {
      clearerr ( fileto ) ; 
      ns_shifr  . string_exception  = ( ns_shifr . localerus ? 
        (char const (*)[]) & u8"ошибка записи заголовка" :
        (char const (*)[]) & "header write error" ) ;
      longjmp(ns_shifr  . jump,1); }
    if ( flagtext ) { // заголовок : "2\n" 
      size_t writecount = fwrite ( & ns_shifr.raspr4 . headertxt  , 1 ,
        sizeof ( ns_shifr.raspr4 . headertxt ) , fileto ) ;
      if ( writecount < sizeof ( ns_shifr.raspr4 . headertxt ) ) {
        clearerr ( fileto ) ; 
        ns_shifr  . string_exception  = ( ns_shifr . localerus ?
          (char const (*)[]) & u8"ошибка записи заголовка" :
          (char const (*)[]) & "header write error" ) ;
        longjmp(ns_shifr  . jump,1); } }
    else { // заголовок : 0x02 + 0x00 
      size_t writecount = fwrite ( & ns_shifr.raspr4 . headerbyn , 1 ,
        sizeof ( ns_shifr.raspr4 . headerbyn ) , fileto ) ;
      if ( writecount < sizeof ( ns_shifr.raspr4 . headerbyn ) ) {
        clearerr ( fileto ) ; 
        ns_shifr  . string_exception  = ( ns_shifr . localerus ?
          (char const (*)[]) & u8"ошибка записи заголовка" :
          (char const (*)[]) & "header write error" ) ;
        longjmp(ns_shifr  . jump,1); } }   
    int bytecount = 0 ;
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
      uint8_t secretdata [ 4 ] = { [0]  = buf&3 ,[1]=(buf>>2)&3,[2]=(buf>>4)&3,
        [3]=(buf>>6)&3} ;
      uint8_t secretdatasole  [ 4 ] ;
      datasole ( & secretdata , & secretdatasole , 4 )  ;
      uint8_t encrypteddata [ 4 ] ;
      crypt_decrypt ( & secretdatasole , & shifr , & encrypteddata , 4 ) ;
      
      for ( int i = 0 ; i < 4 ; i +=  2 ) {
        
        buf = (encrypteddata [ i ] & 0xf) bitor ((encrypteddata [ i + 1 ] & 0xf) << 4) ;
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
          break ; }             }
      /*
      buf = (encrypteddata [ 2 ] & 0xf) bitor ((encrypteddata [ 3 ] & 0xf) << 4) ;
      if(flagtext) {
        char buf2[2];
        char_to_hex(buf,&buf2);
        writecount = fwrite ( & buf2 , 2 , 1 , fileto ) ;
        bytecount +=  2 ;
        if ( bytecount == 24 )  {
          bytecount = 0 ;
          buf2[0] = '\n' ;
          fwrite ( & (buf2[0]) , 1 , 1 , fileto ) ; }  }
      else
        writecount = fwrite ( & buf , 1 , 1 , fileto ) ;
      if ( writecount == 0 ) {
        if ( ferror ( fileto ) ) {
          clearerr ( fileto ) ;
          ns_shifr  . string_exception  = ( ns_shifr . localerus ?
            (char const (*)[]) & u8"ошибка записи в файл" :
            (char const (*)[]) & "error writing to file" ) ;
          longjmp(ns_shifr  . jump,1); }
        break ; }*/
        
    } while ( true ) ; 
    if ( flagtext and bytecount ) {
      char buf = '\n' ;
      fwrite ( & buf , 1 , 1 , fileto ) ; } }
  else  { // декодируем
    // главный заголовок должен быть "шифр" без конца строки
    unsigned char buf [ sizeof ( ns_shifr . mainheader ) ] ;
//printf("sizeof ( ns_shifr . mainheader )=%zd\n",sizeof ( ns_shifr . mainheader ));    
    size_t readcount = fread ( & buf , 1 ,
      sizeof ( ns_shifr . mainheader ) , filefrom ) ;
//printf("0.readcount=%zd\n",readcount);      
    if ( readcount < sizeof ( ns_shifr . mainheader ) ) {
      if ( ferror ( filefrom ) ) clearerr ( filefrom ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"ошибка чтения заголовка" :
        (char const (*)[]) & "read header error");
      longjmp(ns_shifr  . jump,1); }
    if ( memcmp ( & ( ns_shifr . mainheader [ 0 ] ) , & ( buf [ 0 ] ) ,
      sizeof ( ns_shifr . mainheader ) ) ) {
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"плохой заголовок" :
        (char const (*)[]) & "bad header" ) ;
      longjmp(ns_shifr  . jump,1); }
    // 0x02,0x00 или "2\n"    
//printf("sizeof ( ns_shifr.raspr4 . headerbyn )=%zd\n",sizeof ( ns_shifr.raspr4 . headerbyn ));    
    readcount = fread ( & buf , 1 ,
      sizeof ( ns_shifr.raspr4 . headerbyn ) , filefrom ) ;
//printf("1.readcount=%zd\n",readcount);      
    if ( readcount < sizeof ( ns_shifr.raspr4 . headerbyn ) ) {
      if ( ferror ( filefrom ) ) clearerr ( filefrom ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        (char const (*)[]) & u8"ошибка чтения заголовка" :
        (char const (*)[]) & "read header error");
      longjmp(ns_shifr  . jump,1); }
    if ( memcmp ( & ( ns_shifr.raspr4 . headerbyn [ 0 ] ) , & ( buf [ 0 ] ) ,
      sizeof ( ns_shifr.raspr4 . headerbyn ) ) ) {
      if ( memcmp ( & ( ns_shifr.raspr4 . headertxt [ 0 ] ) , & ( buf [ 0 ] ) ,
        sizeof ( ns_shifr.raspr4 . headertxt ) ) ) {
          ns_shifr  . string_exception  = ( ns_shifr . localerus ?
            (char const (*)[]) & u8"плохой заголовок" :
            (char const (*)[]) & "bad header" ) ;
        longjmp(ns_shifr  . jump,1); }
      else  flagtext  = true  ; }
    else  flagtext  = false ;
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
            ( buf4[0] < 'a' or buf4[0] > 'f')) ;
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
          if (not(( (*i) >= '0' and (*i) <= '9') or ((*i) >= 'a' and (*i) <= 'f'))) {
            ns_shifr  . string_exception  = ( ns_shifr . localerus ?
              (char const (*)[]) & u8"ошибка hex данных" :
              (char const (*)[]) & "error hex data" ) ;
            longjmp(ns_shifr  . jump,1); } }
//printf("buf4=[%c,%c,%c,%c]\n",buf4[0],buf4[1],buf4[2],buf4[3]);
        hex_to_char ( ( char const ( * ) [ 2 ] ) ( & buf4 ) ,
          & ( buf [ 0 ] ) ) ;  
        hex_to_char ( ( char const ( * ) [ 2 ] ) ( & ( buf4 [ 2 ] ) ) ,
          & ( buf [ 1 ] ) ) ; }
      else {
        readcount = fread ( & (buf[0]) , 1 , 2 , filefrom ) ;
//printf("2.readcount=%zd\n",readcount);        
        if ( readcount < 2 ) {
          if ( feof ( filefrom  ) ) break ;
          if ( ferror ( filefrom ) ) {
            clearerr ( filefrom ) ;
            ns_shifr  . string_exception  = ( ns_shifr . localerus ?
              (char const (*)[]) & u8"ошибка чтения файла" :
              (char const (*)[]) & "error reading file" ) ;
            longjmp(ns_shifr  . jump,1); }
          break ; } }
      uint8_t secretdata [ 4 ] = { [0]  = buf[0]&0xf ,[1]=(buf[0]>>4)&0xf ,
        [2]  = buf[1]&0xf ,[3]=(buf[1]>>4)&0xf      } ;
      uint8_t decrypteddata [ 4 ] ;
      crypt_decrypt ( & secretdata , & deshi , & decrypteddata , 4 ) ;
      buf[0] = (decrypteddata [ 0 ] & 0x3) bitor ((decrypteddata [ 1 ] & 0x3) << 2)
        bitor ((decrypteddata [ 2 ] & 0x3)<<4) bitor
        ((decrypteddata [ 3 ] & 0x3) << 6);
      size_t writecount = fwrite ( & (buf[0]) , 1 , 1 , fileto ) ;
/*printf("fileto = %p = [ ",fileto);            
for ( uint8_t const * i = ( uint8_t const * ) fileto ;
  i < ( uint8_t const * const ) ( fileto + 1 ) ; ++  i )
  printf("%x , ",(unsigned int)(*i));
puts("]");                  */
      if ( writecount == 0 ) {
        if ( ferror ( fileto ) ) {
          clearerr ( fileto ) ;
          ns_shifr  . string_exception  = ( ns_shifr . localerus ?
            (char const (*)[]) & u8"ошибка записи файла" :
            (char const (*)[]) & "error writing file" ) ;
          longjmp(ns_shifr  . jump,1); }
        break ; }
    } while ( true ) ; } } // shifr deshi
out : ;  
  int resulterror  = 0 ;
//printf(u8"закрываю выход\n");
  if ( flagclosefileto  ) {
/*printf("flagclosefileto:fileto = %p\n",fileto);            
printf("fileto = %p = [ ",fileto);            
for ( uint8_t const * i = ( uint8_t const * ) fileto ;
  i < ( uint8_t const * const ) ( fileto + 1 ) ; ++  i )
  printf("%x , ",(unsigned int)(*i));
puts("]");                  */
    if  ( fclose  ( fileto  ) ) {
      int e = errno ;
      fprintf  (  stderr, ( ns_shifr . localerus ?
        u8"Ошибка закрытия файла записи \"%s\" : %s\n" :
        "Error closing file to writing \"%s\" : %s\n" ) ,
        & ( ( * outputfilename ) [ 0 ] ) , strerror  ( e ) ) ;
      resulterror = 1 ; } }
//printf(u8"закрываю вход\n");
  if ( flagclosefilefrom ) {
//printf("flagclosefilefrom:filefrom = %p\n",filefrom);            
    if  ( ( not feof ( filefrom ) ) and fclose  ( filefrom ) ) {
      int e = errno ; 
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка закрытия файла чтения \"%s\" : %s\n" :
        "Error closing file of reading \"%s\" : %s\n"),
        &((*inputfilename)[0]),strerror(e));
      resulterror = 2 ; } }
//puts("shifr_destr");      
  shifr_destr ( ) ;
  return  resulterror ; 
  
}
