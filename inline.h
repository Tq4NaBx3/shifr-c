// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# ifndef  SHIFR_INLINE_H
# define  SHIFR_INLINE_H

# include <iso646.h> // not_eq
# include <string.h> // strcmp
# include "define.h"
# ifdef SHIFR_DEBUG
# include <sys/time.h> // gettimeofday
# endif
# include "struct.h"
# include "public.h"
# include "inline-pri.h"

# define  shifr_number_def_elt_copy( N ) \
uint8_t shifr_number ## N ## _elt_copy  ( \
  shifr_number_type ( N ) const * const np  , uint8_t const i ) { \
  return  shifr_number_const_pub_to_priv ( N ) ( np ) -> arr [ i ] ; }

# define  shifr_number_elt_copy( N ) shifr_number ## N ## _elt_copy

static  inline  shifr_number_def_elt_copy ( v2 )
static  inline  shifr_number_def_elt_copy ( v3 )

# define  shifr_number_def_add(  N , D ) \
void  shifr_number ## N ## _add  ( shifr_number_type ( N ) * const restrict  np  , \
  shifr_number_type ( N ) const * const restrict  xp ) {  \
  uint8_t per = 0 ; \
  uint8_t i = 0 ; \
  do  { \
    uint16_t const s = ( uint16_t  ) ( ( ( uint16_t  ) (  \
      shifr_number_elt_copy ( N ) ( np , i ) ) ) + \
      ( ( uint16_t  ) shifr_number_elt_copy ( N ) ( xp , i ) ) + \
      ( ( uint16_t  ) per ) ) ; \
    if ( s >= 0x100  ) {  \
      shifr_number_pub_to_priv ( N ) ( np ) -> arr [ i ] = ( uint8_t ) ( s - 0x100 ) ; \
      per = 1 ; } \
    else  { \
      shifr_number_pub_to_priv ( N ) ( np ) -> arr [ i ] = ( uint8_t ) s  ;  \
      per = 0 ;  }  \
    ++ i  ; \
  } while ( i < D ) ; }

# define  shifr_number_add( N ) shifr_number ## N ## _add

static  inline  shifr_number_def_add  ( v2 , shifr_number_size2 )
static  inline  shifr_number_def_add  ( v3 , shifr_number_size3 )

# define  shifr_number_def_not_zero(  N , D ) \
bool  shifr_number ## N ## _not_zero  ( \
  shifr_number_type ( N ) const * const np  ) { \
  uint8_t const * i = & ( shifr_number_const_pub_to_priv ( N ) ( np ) -> arr [ D ] ) ; \
  do {  \
    --  i ; \
    if ( * i )  \
      return  true  ; \
  } while ( i not_eq & ( shifr_number_const_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) ) ;  \
  return  false ; }

# define  shifr_number_not_zero( N ) shifr_number ## N ## _not_zero

static  inline  shifr_number_def_not_zero ( v2 , shifr_number_size2 )
static  inline  shifr_number_def_not_zero ( v3 , shifr_number_size3 )

# define  shifr_number_def_dec(  N , D ) \
void  shifr_number ## N ## _dec ( shifr_number_type ( N ) * const np  ) { \
  uint8_t  * i = & ( shifr_number_pub_to_priv ( N ) ( np ) -> arr [ 0 ] ) ; \
  do {  \
    if ( ( * i ) == 0 ) \
      ( * i ) = 0xffU ; \
    else  { \
      -- ( * i ) ;  \
      break ; } \
    ++  i ; \
  } while ( i not_eq & ( shifr_number_pub_to_priv ( N ) ( np ) -> arr [ D ] ) ) ; }

# define  shifr_number_dec( N ) shifr_number ## N ## _dec

static  inline  shifr_number_def_dec  ( v2 , shifr_number_size2 )
static  inline  shifr_number_def_dec  ( v3 , shifr_number_size3 )

# define  shifr_number_def_div_mod(  N , D ) \
uint8_t shifr_number ## N ## _div_mod ( \
  shifr_number_type ( N ) * const np0 , uint8_t const div ) { \
  shifr_number_priv_type ( N ) * const np = shifr_number_pub_to_priv ( N ) ( np0 ) ; \
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

# define  shifr_number_div_mod( N ) shifr_number ## N ## _div_mod

static  inline  shifr_number_def_div_mod  ( v2 , shifr_number_size2 )
static  inline  shifr_number_def_div_mod  ( v3 , shifr_number_size3 )

# define  shifr_number_def_set_byte(  N , D ) \
void  shifr_number ## N ## _set_byte  ( shifr_number_type ( N ) * const np0 , \
  uint8_t const x ) { \
  shifr_number_priv_type ( N ) * const np = shifr_number_pub_to_priv ( N ) ( np0 ) ; \
  memset  ( & ( np -> arr [ 1 ] ) , 0 , D - 1 ) ; \
  np -> arr [ 0 ] = x ; }

# define  shifr_number_set_byte( N ) shifr_number ## N ## _set_byte

static  inline  shifr_number_def_set_byte ( v2 , shifr_number_size2 )
static  inline  shifr_number_def_set_byte ( v3 , shifr_number_size3 )

static  inline  void  shifr_generate_password ( t_ns_shifr * const ns_shifrp ) {
  switch  ( ns_shifrp -> use_version  ) {
    case  2 : 
      shifr_generate_pass2  ( ns_shifrp ) ;
      shifr_pass_to_array2  ( ns_shifrp ) ;
# ifdef SHIFR_DEBUG
      fputs ( ( ns_shifrp -> localerus ?
        u8"generate_password:внутренний пароль = " :
        "generate_password:internal password = " ) , stderr ) ;
      shifr_number_princ  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif
      break ;
    case 3 :
      shifr_generate_pass3  ( ns_shifrp ) ;
      shifr_pass_to_array3  ( ns_shifrp ) ;
# ifdef SHIFR_DEBUG
      fputs ( ( ns_shifrp -> localerus ?
        u8"generate_password:внутренний пароль = " :
        "generate_password:internal password = " ) , stderr ) ;
      shifr_number_princ  ( v3 ) ( & ns_shifrp -> raspr3  . pass . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif
      break ;
    default :
      fprintf ( stderr , ( ns_shifrp -> localerus ?
        u8"generate_password:неопознанная версия : \'%d\'\n" :
        "generate_password:unrecognized version : \'%d\'\n" ) ,
        ns_shifrp -> use_version ) ;
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) & u8"generate_password:неопознанная версия" :
        ( shifr_strcp ) & "generate_password:unrecognized version" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; } }

static  inline  void  shifr_streambuf_init  ( shifr_t_streambuf * const me  ,
  FILE  * const f ) {
  me -> file  = f ;
  me -> buf = 0 ;
  me -> bufbitsize = 0 ;
  me -> bytecount = 0 ; }
      
static  inline  void  shifr_enter_password2 ( t_ns_shifr * const ns_shifrp ) {
  char  volatile  p40 [ shifr_password_letters2size ] ;
  shifr_set_keypress  ( ns_shifrp ) ;
  fgets ( ( char  * ) & ( p40 [ 0 ] ) , shifr_password_letters2size , stdin ) ;
  shifr_reset_keypress ( ns_shifrp ) ;
  char volatile * j = & ( p40 [ 0 ]  ) ;
  while ( ( ( * j ) not_eq '\n' ) and
    ( ( * j ) not_eq '\00' ) and
    ( j < ( & ( p40 [ shifr_password_letters2size ] ) ) ) )
    ++ j ;  
  if ( j < ( & ( p40 [ shifr_password_letters2size ] ) ) )
    ( * j ) = '\00' ;
  else  {
    shifr_memsetv ( p40 , shifr_memsetv_default_byte , sizeof  ( p40 ) ) ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & u8"в пароле нет конца строки" :
      ( shifr_strcp ) & "there is no end of line in the password" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  switch ( ns_shifrp -> password_alphabet ) {
  case  shifr_letters_count  :
    shifr_string_to_password_templ  ( v2 ) ( ns_shifrp , ( shifr_strvcp ) & p40 , 
      & ns_shifrp -> raspr2  . pass . pub , ( shifr_strcp ) & ns_shifrp -> letters ,
      shifr_letters_count ) ;
    break ;
  case  shifr_letters_count2  :
    shifr_string_to_password_templ  ( v2 ) ( ns_shifrp , ( shifr_strvcp ) & p40 , 
      & ns_shifrp -> raspr2  . pass . pub , ( shifr_strcp ) & ns_shifrp -> letters2 ,
      shifr_letters_count2 ) ;
    break ;
  case  shifr_letters_count3  :
    shifr_string_to_password_templ  ( v2 ) ( ns_shifrp , ( shifr_strvcp ) & p40 , 
      & ns_shifrp -> raspr2  . pass . pub , ( shifr_strcp ) & ns_shifrp -> letters3 ,
      shifr_letters_count3 ) ;
    break ;
  case  shifr_letters_count4  :
    shifr_string_to_password_templ  ( v2 ) ( ns_shifrp , ( shifr_strvcp ) & p40 , 
      & ns_shifrp -> raspr2  . pass . pub , ( shifr_strcp ) & ns_shifrp -> letters4 ,
      shifr_letters_count4 ) ;
    break ;
  default :
    shifr_memsetv ( p40 , shifr_memsetv_default_byte , sizeof  ( p40 ) ) ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & u8"неизвестный алфавит пароля" :
      ( shifr_strcp ) & "unknown password alphabet" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  char  volatile  password_letters [ shifr_password_letters2size ] ;
  switch  ( ns_shifrp -> password_alphabet  ) {
  case  shifr_letters_count :
    shifr_password_to_string_templ  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
      & password_letters , & ns_shifrp -> letters , shifr_letters_count ) ;
    break ;
  case  shifr_letters_count2  :
    shifr_password_to_string_templ  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
      & password_letters , & ns_shifrp -> letters2 , shifr_letters_count2 ) ;
    break ;
  case  shifr_letters_count3  :
    shifr_password_to_string_templ  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
      & password_letters , & ns_shifrp -> letters3 , shifr_letters_count3 ) ;
    break ;
  case  shifr_letters_count4  :
    shifr_password_to_string_templ  ( v2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
      & password_letters , & ns_shifrp -> letters4 , shifr_letters_count4 ) ;
    break ;
  default :
    shifr_memsetv ( p40 , shifr_memsetv_default_byte , sizeof  ( p40 ) ) ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & u8"неизвестный алфавит пароля" :
      ( shifr_strcp ) & "unknown password alphabet" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  if  ( strcmp ( ( char * ) & ( password_letters  [ 0 ] ) ,
    ( char * ) & ( p40 [ 0 ] ) ) )
    fprintf  ( stderr , ( ns_shifrp -> localerus ?
      u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
      "Warning! Password \'%s\' is very large. Same as \'%s\'\n" )
      , & ( p40 [ 0 ] ) , & ( password_letters [ 0 ] ) ) ;
  shifr_memsetv ( p40 , shifr_memsetv_default_byte , sizeof  ( p40 ) ) ;
  shifr_memsetv ( password_letters  , shifr_memsetv_default_byte ,
    sizeof  ( password_letters  ) ) ; }

static  inline  void  shifr_enter_password3 ( t_ns_shifr * const ns_shifrp ) {
  char  volatile  p60 [ shifr_password_letters3size ] ;
  shifr_set_keypress  ( ns_shifrp ) ;
  fgets ( ( char  * ) & ( p60 [ 0 ] ) , shifr_password_letters3size , stdin ) ;
  shifr_reset_keypress ( ns_shifrp ) ;
  char  volatile  * j = & ( p60 [ 0 ] ) ;
  while ( ( ( * j ) not_eq '\n' ) and
    ( ( * j ) not_eq '\00' ) and
    ( j < ( & ( p60 [ shifr_password_letters3size ] ) ) ) )
    ++ j ;  
  if ( j < ( & ( p60 [ shifr_password_letters3size ] ) ) )
    ( * j ) = '\00' ;
  else  {
    shifr_memsetv ( p60 , shifr_memsetv_default_byte , sizeof  ( p60 ) ) ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & u8"в пароле нет конца строки" :
      ( shifr_strcp ) & "there is no end of line in the password" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  char  volatile  password_letters6 [ shifr_password_letters3size ] ;
  switch  ( ns_shifrp -> password_alphabet  ) {
  case  shifr_letters_count :
    shifr_string_to_password_templ  ( v3 ) ( ns_shifrp , ( shifr_strvcp ) & p60 ,
      & ns_shifrp -> raspr3  . pass . pub ,
      ( shifr_strcp ) & ns_shifrp -> letters ,  shifr_letters_count ) ;
    shifr_password_to_string_templ  ( v3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
      & password_letters6 , & ns_shifrp -> letters , shifr_letters_count ) ;
    break ;
  case  shifr_letters_count2  :
    shifr_string_to_password_templ  ( v3 ) ( ns_shifrp , ( shifr_strvcp ) & p60 ,
      & ns_shifrp -> raspr3  . pass . pub ,
      ( shifr_strcp ) & ns_shifrp -> letters2 , shifr_letters_count2 ) ;
    shifr_password_to_string_templ  ( v3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
      & password_letters6 , & ns_shifrp -> letters2 , shifr_letters_count2 ) ;
    break ;
  case  shifr_letters_count3  :
    shifr_string_to_password_templ  ( v3 ) ( ns_shifrp , ( shifr_strvcp ) & p60 ,
      & ns_shifrp -> raspr3  . pass . pub ,
      ( shifr_strcp ) & ns_shifrp -> letters3 ,  shifr_letters_count3 ) ;
    shifr_password_to_string_templ  ( v3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
      & password_letters6 , & ns_shifrp -> letters3 , shifr_letters_count3 ) ;
    break ;
  case  shifr_letters_count4  :
    shifr_string_to_password_templ  ( v3 ) ( ns_shifrp , ( shifr_strvcp ) & p60 ,
      & ns_shifrp -> raspr3  . pass . pub ,
      ( shifr_strcp ) & ns_shifrp -> letters4 , shifr_letters_count4 ) ;
    shifr_password_to_string_templ  ( v3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
      & password_letters6 , & ns_shifrp -> letters4 , shifr_letters_count4 ) ;
    break ;
  default :
    shifr_memsetv ( p60 , shifr_memsetv_default_byte , sizeof  ( p60 ) ) ;
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( shifr_strcp ) & u8"неизвестный алфавит пароля" :
      ( shifr_strcp ) & "unknown password alphabet" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  if  ( strcmp ( ( char * ) & ( password_letters6 [ 0 ] ) , ( char * ) & ( p60 [ 0 ] ) ) )
    fprintf  ( stderr , ( ns_shifrp -> localerus ?
      u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'.\n" :
      "Warning! Password \'%s\' is very large. Same as \'%s\'.\n" )
      , & ( p60 [ 0 ] ) , & ( password_letters6  [ 0 ] ) ) ;
  shifr_memsetv ( p60 , shifr_memsetv_default_byte , sizeof  ( p60 ) ) ;
  shifr_memsetv ( password_letters6 , shifr_memsetv_default_byte ,
    sizeof  ( password_letters6 ) ) ; }
      
static  inline  void  shifr_enter_password ( t_ns_shifr * const ns_shifrp ) {
  switch ( ns_shifrp -> use_version ) {
    case  3 :
      shifr_enter_password3  ( ns_shifrp ) ;
      break ;
    case 2 :
      shifr_enter_password2  ( ns_shifrp ) ;
      break ;
    default :
      fprintf ( stderr  , ( ns_shifrp -> localerus ?
        u8"enter_password:Неизвестная версия %d\n" :
        "enter_password:Unknown version %d\n" ) , ns_shifrp -> use_version  ) ;
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( shifr_strcp ) & u8"enter_password:Неизвестная версия" :
        ( shifr_strcp ) & "enter_password:Unknown version" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; } }

static inline void  shifr_init ( t_ns_shifr * const ns_shifrp ) {
  ( * ns_shifrp ) = ( t_ns_shifr ) {
    . use_version  = 3 ,
    . flagtext = false ,
    . password_alphabet = 62 ,
    . old_last_data = 0 ,
    . old_last_sole = 0 ,
    . charcount = 0 ,
    . buf2index = 0 ,
    . bitscount = 0 ,
    } ;
  { char * j = & ( ns_shifrp -> letters [ 0 ] ) ;
    uint8_t i = ' ' ;
    do {
      ( * j ) = ( char  ) i ;
      ++ i  ;
      ++ j  ;
    } while ( i <= '~' ) ; }
  // 0x30 '0' - 0x39 '9' , 0x41 'A' - 0x5a 'Z' , 0x61 'a' - 0x7a 'z'  
  { char * j = & ( ns_shifrp -> letters2 [ 0 ] ) ;
    { uint8_t i = '0' ;
      do {
        ( * j ) = ( char  ) i ;
        ++ i  ;
        ++ j  ;
      } while ( i <= '9' ) ; }
    { uint8_t i = 'A' ;
      do {
        ( * j ) = ( char  ) i ;
        ++ i  ;
        ++ j  ;
      } while ( i <= 'Z'  ) ; }
    { uint8_t i = 'a' ;
      do {
        ( * j ) = ( char  ) i ;
        ++ i  ;
        ++ j  ;
      } while ( i <= 'z'  ) ; } }
  { char * j = & ( ns_shifrp -> letters3  [ 0 ] ) ;
    uint8_t i = '0' ;
    do {
      ( * j ) = ( char  ) i ;
      ++ i  ;
      ++ j  ;
    } while ( i <= '9' ) ; }
  { char * j = & ( ns_shifrp -> letters4  [ 0 ] ) ;
    uint8_t i = 'a' ;
    do {
      ( * j ) = ( char  ) i ;
      ++ i  ;
      ++ j  ;
    } while ( i <= 'z' ) ; }
  ns_shifrp  -> filefrom  = stdin ;
  ns_shifrp  -> fileto = stdout ; }      
      
# ifdef SHIFR_DEBUG

static inline shifr_timestamp_t get_timestamp ( void ) {
  struct timeval now  ;
  gettimeofday (  & now , ( struct timezone * ) 0 ) ;
  return  now . tv_usec + ( shifr_timestamp_t ) now . tv_sec * 1000000LL  ; }

# endif // SHIFR_DEBUG      
      
static  inline  int shifr_show_help ( t_ns_shifr  const * const main_shifrp ) {
  bool  const localerus = main_shifrp -> localerus ;
  puts ( localerus ?
      u8"Шифр ©2020-2 Глебов А.Н.\n"
      u8"Симметричное поточное шифрование с 'солью'.\n"
      u8"'Соль' генерируется постоянно, что даёт хорошую стойкость.\n"
      u8"Размер данных увеличивается в два раза. В три раза в текстовом режиме.\n"
      u8"Нет диагностики неправильного пароля.\n"
      u8"Синтаксис : shifr [параметры]" :
      "Shifr ©2020-2 Glebe A.N.\n"
      "Symmetric stream encryption with 'salt'.\n"
      "'Salt' is constantly generated, which gives good durability.\n"
      "Data size doubles. Tripled in text mode.\n"
      "There is no diagnosis of the wrong password.\n"
      "Syntax : shifr [options]" ) ;
    puts  ( localerus ?
      u8"Параметры :" :
      "Options :"  ) ;
    puts  ( localerus ?
      u8"  --ген-пар или\n  --gen-pas\tгенерировать пароль" :
      "  --gen-pas\tpassword generate" );
    puts  ( localerus ?
      u8"  --зашифр или\n  --encrypt\tзашифровать\t(по-умолчанию)" :
      "  --encrypt\t(by default)" );
    puts  ( localerus ?
      u8"  --расшифр или\n  --decrypt\tрасшифровать" :
      "  --decrypt" );
    puts  ( localerus ?
      u8"  --пар или\n  --pas 'строка_пароля'\tиспользовать данный пароль" :
      "  --pas 'password_string'\tuse this password" );
    puts  ( localerus ?
      u8"  --пар-путь или\n  --pas-path 'путь_к_файлу_с_паролем'\t"
      u8"использовать пароль в файле" :
      "  --pas-path 'path_to_password_file'\tuse password in file" );
    puts  ( localerus ?
      u8"  --вход или < или \n  --input 'имя_файла'\tчитать из файла (без данной опции"
      u8" читаются данные со стандартного входа)" :
      "  --input or < 'file_name'\tread from file (without this option data reads from"
      " standard input)" ) ;
    puts  ( localerus ? 
      u8"  --выход или > или \n  --output 'имя_файла'\tзаписывать в файл (без данной"
      u8" опции записываются данные в стандартный выход)" :
      "  --output or > 'file_name'\twrite to file (without this option data writes to"
      " standard output)"    );
    puts  ( localerus ? 
      u8"  --текст или\n  --text\tшифрованный файл записан текстом ascii" :
      "  --text\tencrypted file written in ascii text"    );
    puts  ( localerus ? 
      u8"  --2\tиспользовать двух битное шифрование, ключ = 45 бит ( 6 - 14 букв )." :
      "  --2\tusing two bit encryption, key = 45 bits ( 6 - 14 letters )." ) ;
    puts  ( localerus ?
      u8"  --3\tиспользовать трёх битное шифрование, ключ = 296 бит ( 45 - 90 букв )."
      u8" ( по-умолчанию )" :
      "  --3\tusing three bit encryption, key = 296 bits ( 45 - 90 letters )."
      " ( by default )") ;
    fputs  ( localerus ?  
      u8"Буквы в пароле (алфавит):\n  --а95 или\n  --a95\t\'" :
      "Letters in password (alphabet):\n  --a95\t\'" , stdout ) ;
    { char const * cj = & ( main_shifrp -> letters [ 0 ] ) ;
      do {
        fputc ( * cj  , stdout  ) ;
        ++ cj ;
      } while ( cj not_eq ( & ( main_shifrp -> letters [ shifr_letters_count ] ) ) ) ; }
    fputs ( ( main_shifrp -> localerus ?
      u8"\'\n  --а62 или\n  --a62\t\'" :
      "\'\n  --a62\t\'" ) , stdout  ) ;
    { char const * cj = & ( main_shifrp -> letters2 [ 0 ] ) ;
      do {
        fputc ( * cj  , stdout  ) ;
        ++ cj ;
      } while ( cj not_eq ( & ( main_shifrp -> letters2 [ shifr_letters_count2 ] ) ) ) ; }
    fputs ( ( main_shifrp -> localerus ?
      u8"\'\t(по умолчанию)\n" :
      "\'\t(by default)\n"  ) , stdout  ) ;

    fputs ( ( main_shifrp -> localerus ?
      u8"  --а26 или\n  --a26\t\'" :
      "\'\n  --a26\t\'" ) , stdout  ) ;
    { char const * cj = & ( main_shifrp -> letters4 [ 0 ] ) ;
      do {
        fputc ( * cj  , stdout  ) ;
        ++ cj ;
      } while ( cj not_eq ( & ( main_shifrp -> letters4 [ shifr_letters_count4 ] ) ) ) ; }
    fputs ( ( main_shifrp -> localerus ?
      u8"\'\n" :
      "\'\n"  ) , stdout  ) ;
      
    fputs ( ( localerus ?
      u8"  --а10 или\n  --a10\t\'" :
      "\'\n  --a10\t\'" ) , stdout  ) ;
    { char const * cj = & ( main_shifrp -> letters3 [ 0 ] ) ;
      do {
        fputc ( * cj  , stdout  ) ;
        ++ cj ;
      } while ( cj not_eq ( & ( main_shifrp -> letters3 [ shifr_letters_count3 ] ) ) ) ; }
    fputs ( ( localerus ?
      u8"\'\n" :
      "\'\n"  ) , stdout  ) ;

    puts  ( localerus ?
      u8"Пример использования :"  :
      "Usage example"  ) ;
    puts  ( localerus ?
      u8"  $ ./shifr --ген-пар > psw"  :
      "  $ ./shifr --gen-pas > psw"  ) ;
    puts  ( 
      "  $ cat psw\n"
      "  n3LTQH4eIicGDNaF8CDVRGdaCEVXxPPgikJ9lbQKW4zs8StkhD"  ) ;
    puts  ( localerus ?
      u8"  $ ./shifr --пар-путь 'psw' > test.shi --текст"  :
      "  $ ./shifr --pas-path 'psw' > test.shi --text"  ) ;
    puts( localerus ?
      u8"  2+2 (Нажимаем Enter,Ctrl+D)" :
      "  2+2 (Press Enter,Ctrl+D)" ) ;
    puts  ( 
      "  $ cat test.shi\n"
      "  ylQ?ncm;ags" ) ;
    puts( localerus ?
      u8"  $ ./shifr --пар-путь 'psw' < test.shi --текст --расшифр" :
      "  $ ./shifr --pas-path 'psw' < test.shi --text --decrypt" ) ;
    puts  ( "  2+2" ) ;
    return 0 ; }      
      
static  inline  int shifr_main_genpsw ( t_ns_shifr  * const main_shifrp ) {
  shifr_generate_password ( main_shifrp ) ;
  bool  const localerus = main_shifrp -> localerus  ;
# ifdef SHIFR_DEBUG    
  switch ( main_shifrp -> use_version ) {
  case  2 :
    fputs ( ( localerus ?
      u8"внутренний пароль = " :
      "internal password = " ) , stderr ) ;
    shifr_number_princ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub , stderr  ) ;
    fputs ( "\n" , stderr ) ;
    break ;
  case  3 :
    fputs ( ( localerus ?
      u8"внутренний пароль = " :
      "internal password = " ) , stderr ) ;
    shifr_number_princ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub , stderr  ) ;
    fputs ( "\n" , stderr ) ;
    break ;
  default :
    fprintf ( stderr , ( localerus ?
      u8"flaggenpasswd : неопознанная версия : \'%d\'\n" :
      "flaggenpasswd : unrecognized version : \'%d\'\n" ) , main_shifrp -> use_version ) ;
    main_shifrp -> string_exception  = ( localerus ?
      ( shifr_strcp ) & u8"flaggenpasswd : неопознанная версия" :
      ( shifr_strcp ) & "flaggenpasswd : unrecognized version" ) ;
    longjmp ( main_shifrp -> jump  , 1 ) ; }
# endif
    char  volatile  password_letters2_62  [ shifr_password_letters2size ] ;
    char  volatile  password_letters3_62  [ shifr_password_letters3size ] ;
    char  volatile  password_letters2_10  [ shifr_password_letters2size ] ;
    char  volatile  password_letters3_10  [ shifr_password_letters3size ] ;
    char  volatile  password_letters2_26  [ shifr_password_letters2size ] ;
    char  volatile  password_letters3_26  [ shifr_password_letters3size ] ;
    switch  ( main_shifrp -> use_version ) {
    case  2 :
      shifr_password_to_string_templ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub ,
        & main_shifrp -> password_letters2 , & main_shifrp -> letters ,
        shifr_letters_count ) ;
      shifr_password_to_string_templ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub ,
        & password_letters2_62  , & main_shifrp -> letters2 , shifr_letters_count2 ) ;
      shifr_password_to_string_templ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub ,
        & password_letters2_10 , & main_shifrp -> letters3 , shifr_letters_count3 ) ;
      shifr_password_to_string_templ  ( v2 ) ( & main_shifrp -> raspr2  . pass . pub ,
        & password_letters2_26  , & main_shifrp -> letters4 , shifr_letters_count4 ) ;
      break ;
    case  3 :
      shifr_password_to_string_templ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub ,
        & main_shifrp -> password_letters3 , & main_shifrp -> letters ,
        shifr_letters_count ) ;
      shifr_password_to_string_templ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub ,
        & password_letters3_62  , & main_shifrp -> letters2 , shifr_letters_count2 ) ;
      shifr_password_to_string_templ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub ,
        & password_letters3_10  , & main_shifrp -> letters3 , shifr_letters_count3 ) ;
      shifr_password_to_string_templ  ( v3 ) ( & main_shifrp -> raspr3  . pass . pub ,
        & password_letters3_26  , & main_shifrp -> letters4 , shifr_letters_count4 ) ;
      break ;
    default :
      fprintf ( stderr , ( localerus ?
        u8"показать пароль : неопознанная версия : \'%d\'\n" :
        "show password : unrecognized version : \'%d\'\n" ) ,
        main_shifrp -> use_version ) ;
      main_shifrp -> string_exception  = ( localerus ?
        ( shifr_strcp ) & u8"показать пароль : неопознанная версия" :
        ( shifr_strcp ) & "show password : unrecognized version" ) ;
      longjmp ( main_shifrp -> jump  , 1 ) ; }
# ifdef SHIFR_DEBUG        
    printf  ( ( localerus ?
      u8"--a95\tбуквами, знаками между кавычек = \'%s\'\n" : 
      "--a95\tby letters, signs between quotes = \'%s\'\n"  ) ,
      & ( ( ( main_shifrp -> use_version == 3 ) ? main_shifrp -> password_letters3 :
        main_shifrp -> password_letters2 ) [ 0 ] ) ) ;
    printf  ( ( localerus ?
      u8"--a62\tбуквами, цифрами между кавычек = \'%s\' (по-умолчанию)\n" : 
      "--a62\tby letters, digits between quotes = \'%s\' (by default)\n"  ) ,
      & ( ( ( main_shifrp -> use_version == 3 ) ? password_letters3_62  :
        password_letters2_62  ) [ 0 ] ) ) ;
    printf  ( ( localerus ?
      u8"--a26\tмаленькими буквами между кавычек = \'%s\'\n" : 
      "--a26\tby small letters between quotes = \'%s\'\n"  ) ,
      & ( ( ( main_shifrp -> use_version == 3 ) ? password_letters3_26 :
        password_letters2_26  ) [ 0 ] ) ) ;
    printf  ( ( localerus ?
      u8"--a10\tцифрами между кавычек = \'%s\'\n" : 
      "--a10\tby digits between quotes = \'%s\'\n"  ) ,
      & ( ( ( main_shifrp -> use_version == 3 ) ? password_letters3_10 :
        password_letters2_10 )  [ 0 ] ) ) ;
    switch  ( main_shifrp -> use_version ) {
    case  2 :
      { shifr_number_priv_type ( v2 ) password2 ;

        shifr_string_to_password_templ  ( v2 ) ( main_shifrp ,
          ( shifr_strvcp  ) & main_shifrp -> password_letters2 ,
          & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters ,
          shifr_letters_count ) ; 
        fputs ( ( localerus ?
          u8"из строки95 во внутренний пароль = " :
          "from string95 to internal password = " ) , stderr ) ;
        shifr_number_princ  ( v2 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        shifr_string_to_password_templ  ( v2 ) ( main_shifrp ,
          ( shifr_strvcp  ) & password_letters2_62  ,
          & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters2 ,
          shifr_letters_count2 ) ;
        fputs ( ( localerus ?
          u8"из строки62 во внутренний пароль = " :
          "from string62 to internal password = " ) , stderr ) ;
        shifr_number_princ  ( v2 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;
        
        shifr_string_to_password_templ  ( v2 ) ( main_shifrp ,
          ( shifr_strvcp  ) & password_letters2_26  ,
          & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters4 ,
          shifr_letters_count4 ) ;
        fputs ( ( localerus ?
          u8"из строки26 во внутренний пароль = " :
          "from string26 to internal password = " ) , stderr ) ;
        shifr_number_princ  ( v2 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        shifr_string_to_password_templ  ( v2 ) ( main_shifrp ,
          ( shifr_strvcp  ) & password_letters2_10 ,
          & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters3 ,
          shifr_letters_count3 ) ;
        fputs ( ( localerus ?
          u8"из строки10 во внутренний пароль = " :
          "from string10 to internal password = " ) , stderr ) ;
        shifr_number_princ  ( v2 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        }
      break ;
    case  3 :
      { shifr_number_priv_type ( v3 ) password2 ;

        shifr_string_to_password_templ  ( v3 ) ( main_shifrp ,
          ( shifr_strvcp  ) & main_shifrp -> password_letters3 ,
          & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters ,
          shifr_letters_count ) ; 
        fputs ( ( localerus ?
          u8"из строки95 во внутренний пароль = " :
          "from string95 to internal password = " ) , stderr ) ;
        shifr_number_princ  ( v3 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        shifr_string_to_password_templ  ( v3 ) ( main_shifrp ,
          ( shifr_strvcp  ) & password_letters3_62  ,
          & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters2 ,
          shifr_letters_count2 ) ;
        fputs ( ( localerus ?
          u8"из строки62 во внутренний пароль = " :
          "from string62 to internal password = " ) , stderr ) ;
        shifr_number_princ  ( v3 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;
        
        shifr_string_to_password_templ  ( v3 ) ( main_shifrp ,
          ( shifr_strvcp  ) & password_letters3_26 ,
          & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters4 ,
          shifr_letters_count4 ) ;
        fputs ( ( localerus ?
          u8"из строки26 во внутренний пароль = " :
          "from string26 to internal password = " ) , stderr ) ;
        shifr_number_princ  ( v3 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        shifr_string_to_password_templ  ( v3 ) ( main_shifrp ,
          ( shifr_strvcp  ) & password_letters3_10 ,
          & password2 . pub , ( shifr_strcp ) & main_shifrp -> letters3 ,
          shifr_letters_count3 ) ;
        fputs ( ( localerus ?
          u8"из строки10 во внутренний пароль = " :
          "from string10 to internal password = " ) , stderr ) ;
        shifr_number_princ  ( v3 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        }
      break ;
    default :
      fprintf ( stderr  , localerus ?
        u8"неизвестная версия %d\n" : "unknown version %d\n"  ,
        main_shifrp -> use_version ) ;
      main_shifrp -> string_exception  = ( localerus ?
        ( shifr_strcp ) & u8"неизвестная версия" :
        ( shifr_strcp ) & "unknown version" ) ;
      longjmp ( main_shifrp -> jump , 1 ) ; }
# else
  switch  ( main_shifrp -> password_alphabet  ) {
  case  letters_count :
    puts  ( ( char * ) & ( ( ( main_shifrp -> use_version == 3 ) ?
      main_shifrp -> password_letters3 : main_shifrp -> password_letters2 ) [ 0 ] ) ) ;
    break ;
  case  letters_count2  :
    puts  ( ( char * ) & ( ( ( main_shifrp -> use_version == 3 ) ? password_letters3_62 :
      password_letters2_62 ) [ 0 ] ) ) ;
    break ;
  case  letters_count3  :
    puts  ( ( char * ) & ( ( ( main_shifrp -> use_version == 3 ) ? password_letters3_10 :
      password_letters2_10 ) [ 0 ] ) ) ;
    break ;
  case  letters_count4  :
    puts  ( ( char * ) & ( ( ( main_shifrp -> use_version == 3 ) ? password_letters3_26 :
      password_letters2_26 ) [ 0 ] ) ) ;
    break ;
  default :
    main_shifrp -> string_exception  = ( localerus ?
      ( strcp ) & u8"неизвестный алфавит пароля" :
      ( strcp ) & "unknown password alphabet" ) ;
    longjmp ( main_shifrp -> jump , 1 ) ; }
# endif
    shifr_memsetv ( main_shifrp -> password_letters2  , shifr_memsetv_default_byte ,
      sizeof  ( main_shifrp -> password_letters2  ) ) ;
    shifr_memsetv ( main_shifrp -> password_letters3  , shifr_memsetv_default_byte ,
      sizeof  ( main_shifrp -> password_letters3  ) ) ;
    shifr_memsetv ( password_letters2_62  , shifr_memsetv_default_byte ,
      sizeof  ( password_letters2_62  ) ) ;
    shifr_memsetv ( password_letters3_62  , shifr_memsetv_default_byte ,
      sizeof  ( password_letters3_62  ) ) ;
    shifr_memsetv ( password_letters2_26  , shifr_memsetv_default_byte ,
      sizeof  ( password_letters2_26  ) ) ;
    shifr_memsetv ( password_letters3_26  , shifr_memsetv_default_byte ,
      sizeof  ( password_letters3_26  ) ) ;
    shifr_memsetv ( password_letters2_10  , shifr_memsetv_default_byte ,
      sizeof  ( password_letters2_10  ) ) ;
    shifr_memsetv ( password_letters3_10  , shifr_memsetv_default_byte ,
      sizeof  ( password_letters3_10  ) ) ;
    return  0 ; }      
      
static  inline  void  shifr_test_password ( t_ns_shifr  * const main_shifrp ,
  size_t  const nr  ) {
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
              break ; } } }
        break ;
      case  shifr_letters_count2  :
        { size_t i  = 0 ;
          char  volatile  psw_unii  ;
          for ( ; i < nr  ; ++  i ) {
            psw_unii  = psw_uni [ i ] ;
            if ( ( psw_unii < '0' or  psw_unii > '9' ) and
              ( psw_unii < 'a' or psw_unii > 'z' ) and
              ( psw_unii < 'A' or psw_unii > 'Z' ) ) {
              psw_uni [ i ] = '\00' ;
              break ; } }
          psw_unii  = shifr_memsetv_default_byte ; }
        break ;
      case  shifr_letters_count3  :
        { size_t i  = 0 ;
          for ( ; i < nr  ; ++  i ) {
            if (  psw_uni [ i ] < '0' or  psw_uni  [ i ] > '9' ) {
              psw_uni [ i ] = '\00' ;
              break ; } } }
        break ;
      case  shifr_letters_count4  :
        { size_t i  = 0 ;
          for ( ; i < nr  ; ++  i ) {
            if (  psw_uni [ i ] < 'a' or  psw_uni  [ i ] > 'z' ) {
              psw_uni [ i ] = '\00' ;
              break ; } } }
        break ;
      default :
        main_shifrp -> string_exception  = ( main_shifrp -> localerus ?
          ( shifr_strcp ) & u8"неизвестный алфавит пароля" :
          ( shifr_strcp ) & "unknown password alphabet" ) ;
        longjmp ( main_shifrp -> jump  , 1 ) ; } }

static  inline  void  shifr_encode_file_v3  ( t_ns_shifr  * const main_shifrp ,
  uint8_t ( * const inputbufferp  ) [ ] , size_t  const inputbuffersize ,
  uint8_t ( * const outputbufferp ) [ ] , size_t  const outputbuffersize  ) {
    size_t  writecount  ;
    shifr_size_io sizeio  ;
    do  {
      size_t const  readcount = fread ( & ( (*inputbufferp) [ 0 ] ) , 1 , inputbuffersize ,
        main_shifrp -> filefrom ) ;
      if ( readcount  ) {
          sizeio  = shifr_encrypt3  ( main_shifrp ,
            ( shifr_arrcps ) { .cp = ( shifr_arrcp ) inputbufferp , .s = readcount } ,
            ( shifr_arrps ) { .p = outputbufferp , .s = outputbuffersize } ) ;
# ifdef SHIFR_DEBUG
        if ( sizeio . i < readcount ) {
          fprintf ( stderr  , "sizeio . i = %zu , readcount = %zu\n"  , sizeio . i ,
            readcount ) ;
          main_shifrp -> string_exception  = ( shifr_strcp ) & "sizeio . i < readcount" ;
          longjmp ( main_shifrp -> jump  , 1 ) ; }
        if ( sizeio . o > outputbuffersize ) {
          fprintf ( stderr  , "sizeio . o = %zu , outputbuffersize = %zu\n"  ,
            sizeio . o , outputbuffersize ) ;
          main_shifrp -> string_exception  = ( shifr_strcp ) &
            "sizeio . o > outputbuffersize" ;
          longjmp ( main_shifrp -> jump  , 1 ) ; }
# endif // SHIFR_DEBUG
        writecount = fwrite ( & ( (*outputbufferp) [ 0 ] ) , sizeio . o , 1 ,
          main_shifrp -> fileto ) ;
        if ( writecount == 0 ) {
          main_shifrp -> string_exception  = ( main_shifrp -> localerus ?
            ( shifr_strcp ) & u8"v3:ошибка записи в файл" :
            ( shifr_strcp ) & "v3:error writing to file" ) ;
          longjmp ( main_shifrp -> jump  , 1 ) ; }
        if ( feof ( main_shifrp -> filefrom ) ) 
          break ; }
      else {
        if ( ferror ( main_shifrp -> filefrom ) ) {
          main_shifrp -> string_exception  = ( main_shifrp -> localerus ?
            ( shifr_strcp ) & u8"ошибка чтения файла" :
            ( shifr_strcp ) & "error reading the file" ) ;
          longjmp ( main_shifrp -> jump  , 1 ) ; }
        break ; }
    } while ( true ) ;      
      { uint8_t const bytes = shifr_streambuf_writeflushzero3 ( main_shifrp ,
          ( shifr_arrps ) { .p = outputbufferp , .s = outputbuffersize } ) ;
        if ( bytes ) {
          writecount = fwrite ( & ( (*outputbufferp) [ 0 ] ) , bytes , 1 ,
            main_shifrp -> fileto ) ;
          if ( writecount == 0 ) {
            main_shifrp -> string_exception  = ( main_shifrp -> localerus ?
              ( shifr_strcp ) & u8"v3:ошибка записи в файл ( writecount == 0 )" :
              ( shifr_strcp ) & "v3:error writing to file ( writecount == 0 )" ) ;
            longjmp ( main_shifrp -> jump  , 1 ) ; } } } }

static  inline  void  shifr_encode_file_v2 ( t_ns_shifr  * const main_shifrp ,
  uint8_t ( * const inputbufferp  ) [ ] , size_t  const inputbuffersize ,
  uint8_t ( * const outputbufferp ) [ ] , size_t  const outputbuffersize  ) {
    size_t  writecount  ;
    shifr_size_io sizeio  ;
    do  {
      size_t const  readcount = fread ( & ( (* inputbufferp) [ 0 ] ) , 1 , inputbuffersize
        , main_shifrp -> filefrom ) ;
      if ( readcount  ) {
          sizeio  = shifr_encrypt2  ( main_shifrp ,
            ( shifr_arrcps ) { .cp = ( shifr_arrcp ) inputbufferp , .s = readcount } ,
            ( shifr_arrps ) { .p = outputbufferp , .s = outputbuffersize } ) ;
# ifdef SHIFR_DEBUG
        if ( sizeio . i < readcount ) {
          fprintf ( stderr  , "sizeio . i = %zu , readcount = %zu\n"  , sizeio . i ,
            readcount ) ;
          main_shifrp -> string_exception  = ( shifr_strcp ) & "sizeio . i < readcount" ;
          longjmp ( main_shifrp -> jump  , 1 ) ; }
# endif // SHIFR_DEBUG
        writecount = fwrite ( & ( (*outputbufferp) [ 0 ] ) , sizeio . o , 1 ,
          main_shifrp -> fileto ) ;
        if ( writecount == 0 )
          goto Exc ;
        if ( feof ( main_shifrp -> filefrom ) )
          break ; }
      else {
        if ( ferror ( main_shifrp -> filefrom ) ) {
          main_shifrp -> string_exception  = ( main_shifrp -> localerus ?
            ( shifr_strcp ) & u8"ошибка чтения файла" :
            ( shifr_strcp ) & "error reading the file" ) ;
          longjmp ( main_shifrp -> jump  , 1 ) ; }
        break ; }
    } while ( true ) ;
    size_t const sizeout = shifr_encrypt2_flush  ( main_shifrp ,
      ( shifr_arrps ) { .p = outputbufferp , .s = outputbuffersize }  ) ;
    if  ( sizeout ) {
      writecount = fwrite ( & ( (*outputbufferp) [ 0 ] ) , sizeout , 1 ,
        main_shifrp -> fileto ) ;
      if ( writecount == 0 ) {
Exc :
        main_shifrp -> string_exception  = ( main_shifrp -> localerus ?
          ( shifr_strcp ) & u8"ошибка записи в файл" :
          ( shifr_strcp ) & "error writing to file" ) ;
        longjmp ( main_shifrp -> jump  , 1 ) ; } } }            
            
static  inline  void  shifr_decode_file_v2 ( t_ns_shifr  * const main_shifrp ,
  uint8_t ( * const inputbufferp  ) [ ] , size_t  const inputbuffersize ,
  uint8_t ( * const outputbufferp ) [ ] , size_t  const outputbuffersize  ) {
      size_t  writecount  ;
      shifr_size_io sizeio  ;
      do  {
        size_t const  readcount = fread ( & (  (*inputbufferp) [ 0 ] ) , 1 ,
          inputbuffersize , main_shifrp -> filefrom ) ;
        if ( readcount  ) {
          sizeio  = shifr_decrypt2  ( main_shifrp ,
            ( shifr_arrcps ) { .cp = ( shifr_arrcp ) inputbufferp , .s = readcount } ,
            ( shifr_arrps ) { .p = outputbufferp , .s = outputbuffersize } ) ;
# ifdef SHIFR_DEBUG
          if ( sizeio . i < readcount ) {
            fprintf ( stderr  , "sizeio . i = %zu , readcount = %zu\n"  , sizeio . i ,
              readcount ) ;
            main_shifrp -> string_exception  = ( shifr_strcp ) & "sizeio . i < readcount" ;
            longjmp ( main_shifrp -> jump  , 1 ) ; }
# endif // SHIFR_DEBUG
          writecount = fwrite ( & ( (*outputbufferp) [ 0 ] ) , sizeio . o , 1 ,
            main_shifrp -> fileto ) ;
          if ( writecount == 0 ) {
            main_shifrp -> string_exception  = ( main_shifrp -> localerus ?
              ( shifr_strcp ) & u8"ошибка записи в файл" :
              ( shifr_strcp ) & "error writing to file" ) ;
            longjmp ( main_shifrp -> jump  , 1 ) ; }
          if ( feof ( main_shifrp -> filefrom ) )
            break ; } // if readcount
        else {
          if ( ferror ( main_shifrp -> filefrom ) ) {
            main_shifrp -> string_exception  = ( main_shifrp -> localerus ?
              ( shifr_strcp ) & u8"ошибка чтения файла" :
              ( shifr_strcp ) & "error reading the file" ) ;
            longjmp ( main_shifrp -> jump  , 1 ) ; }
          break ; }
      } while ( true ) ; } // ver 2            
            
static  inline  void  shifr_decode_file_v3 ( t_ns_shifr  * const main_shifrp ,
  uint8_t ( * const inputbufferp  ) [ ] , size_t  const inputbuffersize ,
  uint8_t ( * const outputbufferp ) [ ] , size_t  const outputbuffersize  ) {
      size_t  writecount  ;
      shifr_size_io sizeio  ;
      do  {
        size_t const  readcount = fread ( & ( (* inputbufferp) [ 0 ] ) , 1 ,
          inputbuffersize , main_shifrp -> filefrom ) ;
        if ( readcount  ) {
          sizeio  = shifr_decrypt3  ( main_shifrp ,
            ( shifr_arrcps  ) { . cp  = ( shifr_arrcp ) inputbufferp , . s = readcount } ,
            ( shifr_arrps ) { . p = outputbufferp , . s = outputbuffersize } ) ;
# ifdef SHIFR_DEBUG
          if ( sizeio . i < readcount ) {
            fprintf ( stderr  , "sizeio . i = %zu , readcount = %zu\n"  , sizeio . i ,
              readcount ) ;
            main_shifrp -> string_exception  = ( shifr_strcp ) & "sizeio . i < readcount" ;
            longjmp ( main_shifrp -> jump  , 1 ) ; }
# endif // SHIFR_DEBUG
          writecount = fwrite ( & ( (*outputbufferp) [ 0 ] ) , sizeio . o , 1 ,
            main_shifrp -> fileto ) ;
          if ( writecount == 0 ) {
            main_shifrp -> string_exception  = ( main_shifrp -> localerus ?
              ( shifr_strcp ) & u8"ошибка записи в файл" :
              ( shifr_strcp ) & "error writing to file" ) ;
            longjmp ( main_shifrp -> jump  , 1 ) ; }
          if ( feof ( main_shifrp -> filefrom ) )
            break ; } // if readcount
        else {
          if ( ferror ( main_shifrp -> filefrom ) ) {
            main_shifrp -> string_exception  = ( main_shifrp -> localerus ?
              ( shifr_strcp ) & u8"ошибка чтения файла" :
              ( shifr_strcp ) & "error reading the file" ) ;
            longjmp ( main_shifrp -> jump  , 1 ) ; }
          break ; }
      } while ( true ) ; }            
            
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

# define  shifr_password_load_def(  N , SDS ) \
void  shifr_password_load ( N ) ( shifr_number_type ( N ) const * const password0 , \
  shifr_arrp const shifrp , shifr_arrp const deship ) { \
  shifr_initarr ( shifrp  , 0xff  , SDS ) ; \
  shifr_initarr ( deship  , 0xff  , SDS ) ; \
  uint8_t volatile  arrind  [ SDS ] ; \
  { uint8_t volatile  * arrj  = & ( arrind  [ SDS  ] ) ;  \
    uint8_t j = SDS  ;  \
    do  { \
      --  arrj  ; \
      --  j ; \
      ( * arrj )  = j ; \
    } while ( arrj  not_eq & ( arrind  [ 0 ] ) ) ;  } \
  uint8_t inde  = 0 ; \
  shifr_number_priv_type ( N ) password = * shifr_number_const_pub_to_priv ( N ) ( \
    password0 ) ; \
  do {  \
    { uint8_t const cindex = shifr_number_div_mod ( N ) ( & password . pub ,  \
        (  uint8_t ) ( SDS - inde  ) ) ; \
      uint8_t volatile  * const arrind_cindexp = & (  arrind [ cindex ] ) ; \
      ( * shifrp ) [ inde ] = ( * arrind_cindexp ) ;  \
      ( * deship ) [ * arrind_cindexp ] = inde ;  \
      memmove ( ( uint8_t * ) arrind_cindexp , ( uint8_t * ) arrind_cindexp + 1 , \
        ( size_t  ) ( SDS  - inde  - cindex - 1 ) ) ; } \
    ++ inde  ;  \
  } while ( inde < SDS ) ; \
  shifr_memsetv ( arrind  , shifr_memsetv_default_byte , sizeof  ( arrind  ) ) ; }

static  inline  shifr_password_load_def (  v2 , shifr_deshi_size2 )
static  inline  shifr_password_load_def (  v3 , shifr_deshi_size3 )            
            
# endif //  SHIFR_INLINE_H
