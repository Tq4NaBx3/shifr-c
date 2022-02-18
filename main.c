// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# include <locale.h>
# include <stdio.h>
# include <errno.h>
# include <string.h> // strcmp
# include <iso646.h> // not_eq

# include "define.h"
# include "public.h"
# include "struct.h"
# include "access.h"

# define  generate_password shifr_generate_password
static  inline  void  generate_password ( t_ns_shifr * const ns_shifrp ) {
  switch  ( ns_shifrp -> use_version  ) {
    case  2 : 
      shifr_generate_pass2  ( ns_shifrp ) ;
      shifr_pass_to_array2  ( ns_shifrp ) ;
# ifdef SHIFR_DEBUG
      fputs ( ( ns_shifrp -> localerus ?
        u8"generate_password:внутренний пароль = " :
        "generate_password:internal password = " ) , stderr ) ;
      number_princ  ( number_size2 ) ( & ns_shifrp -> raspr2  . pass . pub , stderr  ) ;
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
      number_princ  ( number_size3 ) ( & ns_shifrp -> raspr3  . pass . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif
      break ;
    default :
      fprintf ( stderr , ( ns_shifrp -> localerus ?
        u8"generate_password:неопознанная версия : \'%d\'\n" :
        "generate_password:unrecognized version : \'%d\'\n" ) ,
        ns_shifrp -> use_version ) ;
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( strcp ) & u8"generate_password:неопознанная версия" :
        ( strcp ) & "generate_password:unrecognized version" ) ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; } }

static  inline  void  streambuf_init  ( t_streambuf * const me  ,
  FILE  * const f ) {
  me -> file  = f ;
  me -> buf = 0 ;
  me -> bufbitsize = 0 ;
  me -> bytecount = 0 ; }

static  inline  void  enter_password2 ( t_ns_shifr * const ns_shifrp ) {
  char p40 [ password_letters2size ] ;
  set_keypress  ( ns_shifrp ) ;
  char ( * const p4 ) [ password_letters2size ] =
    (  char  ( * const ) [ password_letters2size  ] )
    fgets ( & ( p40 [ 0 ] ) , password_letters2size , stdin ) ;
  reset_keypress ( ns_shifrp ) ;
  char * j = & ( ( * p4 ) [ 0 ]  ) ;
  while ( ( ( * j ) not_eq '\n' ) and
    ( ( * j ) not_eq '\00' ) and
    ( j < ( & ( * p4 ) [ password_letters2size ] ) ) )
    ++ j ;  
  if ( j < ( & ( ( * p4 ) [ password_letters2size ] ) ) )
    ( * j ) = '\00' ;
  else  {
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( strcp ) & u8"в пароле нет конца строки" :
      ( strcp ) & "there is no end of line in the password" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  switch ( ns_shifrp -> password_alphabet ) {
  case  letters_count  :
    string_to_password_templ  ( number_size2 ) ( ns_shifrp , ( strcp ) p4 , 
      & ns_shifrp -> raspr2  . pass . pub , ( strcp ) & ns_shifrp -> letters ,
      letters_count ) ;
    break ;
  case  letters_count2  :
    string_to_password_templ  ( number_size2 ) ( ns_shifrp , ( strcp ) p4 , 
      & ns_shifrp -> raspr2  . pass . pub , ( strcp ) & ns_shifrp -> letters2 ,
      letters_count2 ) ;
    break ;
  case  letters_count3  :
    string_to_password_templ  ( number_size2 ) ( ns_shifrp , ( strcp ) p4 , 
      & ns_shifrp -> raspr2  . pass . pub , ( strcp ) & ns_shifrp -> letters3 ,
      letters_count3 ) ;
    break ;
  default :
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( strcp ) & u8"неизвестный алфавит пароля" :
      ( strcp ) & "unknown password alphabet" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  char  password_letters [ 30 ] ;
  switch  ( ns_shifrp -> password_alphabet  ) {
  case  letters_count :
    password_to_string_templ  ( number_size2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
      & password_letters , & ns_shifrp -> letters , letters_count ) ;
    break ;
  case  letters_count2  :
    password_to_string_templ  ( number_size2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
      & password_letters , & ns_shifrp -> letters2 , letters_count2 ) ;
    break ;
  case  letters_count3  :
    password_to_string_templ  ( number_size2 ) ( & ns_shifrp -> raspr2  . pass . pub ,
      & password_letters , & ns_shifrp -> letters3 , letters_count3 ) ;
    break ;
  default :
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( strcp ) & u8"неизвестный алфавит пароля" :
      ( strcp ) & "unknown password alphabet" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  if  ( strcmp ( &  ( password_letters  [ 0 ] ) , & ( ( * p4  ) [ 0 ] ) ) )
    fprintf  ( stderr , ( ns_shifrp -> localerus ?
      u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
      "Warning! Password \'%s\' is very large. Same as \'%s\'\n" )
      , & ( ( * p4  ) [ 0 ] ) , & ( password_letters [ 0 ] ) ) ; }

static  inline  void  enter_password3 ( t_ns_shifr * const ns_shifrp ) {
  char p60 [ 180 ] ;
  set_keypress  ( ns_shifrp ) ;
  char ( * const p6 ) [ 180 ] = (char(*const)[180])
    fgets ( & ( p60 [ 0 ] ) , 180 , stdin ) ;
  reset_keypress ( ns_shifrp ) ;
  char * j = & ( ( * p6 ) [ 0 ]  ) ;
  while ( ( ( * j ) not_eq '\n' ) and
    ( ( * j ) not_eq '\00' ) and
    ( j < ( & ( * p6 ) [ 180 ] ) ) )
    ++ j ;  
  if ( j < ( & ( ( * p6 ) [ 180 ] ) ) )
    ( * j ) = '\00' ;
  else  {
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( strcp ) & u8"в пароле нет конца строки" :
      ( strcp ) & "there is no end of line in the password" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  char  password_letters6 [ 180 ] ;
  switch  ( ns_shifrp -> password_alphabet  ) {
  case  letters_count :
    string_to_password_templ  ( number_size3 ) ( ns_shifrp , ( strcp ) p6 ,
      & ns_shifrp -> raspr3  . pass . pub ,
      ( strcp ) & ns_shifrp -> letters ,  letters_count ) ;
    password_to_string_templ  ( number_size3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
      & password_letters6 , & ns_shifrp -> letters , letters_count ) ;
    break ;
  case  letters_count2  :
    string_to_password_templ  ( number_size3 ) ( ns_shifrp , ( strcp ) p6 ,
      & ns_shifrp -> raspr3  . pass . pub ,
      ( strcp ) & ns_shifrp -> letters2 ,  letters_count2 ) ;
    password_to_string_templ  ( number_size3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
      & password_letters6 , & ns_shifrp -> letters2 , letters_count2 ) ;
    break ;
  case  letters_count3  :
    string_to_password_templ  ( number_size3 ) ( ns_shifrp , ( strcp ) p6 ,
      & ns_shifrp -> raspr3  . pass . pub ,
      ( strcp ) & ns_shifrp -> letters3 ,  letters_count3 ) ;
    password_to_string_templ  ( number_size3 ) ( & ns_shifrp -> raspr3  . pass . pub ,
      & password_letters6 , & ns_shifrp -> letters3 , letters_count3 ) ;
    break ;
  default :
    ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
      ( strcp ) & u8"неизвестный алфавит пароля" :
      ( strcp ) & "unknown password alphabet" ) ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  if  ( strcmp ( &  ( password_letters6 [ 0 ] ) , & ( ( * p6  ) [ 0 ] ) ) )
    fprintf  ( stderr , ( ns_shifrp -> localerus ?
      u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'.\n" :
      "Warning! Password \'%s\' is very large. Same as \'%s\'.\n" )
      , & ( ( * p6  ) [ 0 ] ) , & ( password_letters6  [ 0 ] ) ) ; }

# define  enter_password  shifr_enter_password
static  inline  void  enter_password ( t_ns_shifr * const ns_shifrp ) {
  switch ( ns_shifrp -> use_version ) {
    case  3 :
      enter_password3  ( ns_shifrp ) ;
      break ;
    case 2 :
      enter_password2  ( ns_shifrp ) ;
      break ;
    default :
      fprintf ( stderr  , ( ns_shifrp -> localerus ?
        u8"enter_password:Неизвестная версия %d\n" :
        "enter_password:Unknown version %d\n" ) , ns_shifrp -> use_version  ) ;
      ns_shifrp  -> string_exception  = ( ns_shifrp -> localerus ?
        ( strcp ) & u8"enter_password:Неизвестная версия" :
        ( strcp ) & "enter_password:Unknown version" ) ;
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
  ns_shifrp  -> filefrom  = stdin ;
  ns_shifrp  -> fileto = stdout ; }
  
# ifdef SHIFR_DEBUG

# include <sys/time.h>
typedef long long timestamp_t;

static timestamp_t    get_timestamp ()    {
  struct timeval now;
  gettimeofday (&now, NULL);
  return  now.tv_usec + (timestamp_t)now.tv_sec * 1000000;    }
      
# endif // SHIFR_DEBUG
  
int main  ( int argc , char * argv [ ] )  {
    
  t_ns_shifr  main_shifr  ;
  shifr_init  ( & main_shifr ) ;
  char const * const locale = setlocale ( LC_ALL  , ""  ) ;
  main_shifr . localerus = ( strcmp  ( locale  , "ru_RU.UTF-8" ) ==  0 ) ;
  int exc = setjmp  ( main_shifr  . jump  ) ;
  if ( exc ) {
    fprintf ( stderr  , ( main_shifr . localerus ? u8"Исключение : %s\n" :
      "Exception : %s\n" ) , & ( ( *  main_shifr  . string_exception ) [ 0 ] ) ) ;
    return  1 ; }
    
  bool  flagenc = false ;
  bool  flagdec = false ;
  bool  flagpasswd  = false ;
  bool  flaggenpasswd  = false ;
  bool  flagreadpasswd  = false ;
  bool  flagreadinput = false ;
  bool  flagreadoutput = false ;
  bool  flagreadpasswdfromfile  = false ;
  strcp inputfilename = ( strcp ) & u8""  ;
  strcp outputfilename  = ( strcp ) & u8""  ;
  bool  flaginputfromfile = false ;
  bool  flagoutputtofile  = false ;
  bool  flagclosefilefrom = false ;
  bool  flagclosefileto = false ;
  if  ( argc  <=  1  ) {
    puts ( main_shifr . localerus ?
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
    puts  ( main_shifr . localerus ?
      u8"Параметры :" :
      "Options :"  ) ;
    puts  ( main_shifr . localerus ?
      u8"  --ген-пар или\n  --gen-pas\tгенерировать пароль" :
      "  --gen-pas\tpassword generate" );
    puts  ( main_shifr . localerus ?
      u8"  --зашифр или\n  --encrypt\tзашифровать\t(по-умолчанию)" :
      "  --encrypt\t(by default)" );
    puts  ( main_shifr . localerus ?
      u8"  --расшифр или\n  --decrypt\tрасшифровать" :
      "  --decrypt" );
    puts  ( main_shifr . localerus ?
      u8"  --пар или\n  --pas 'строка_пароля'\tиспользовать данный пароль" :
      "  --pas 'password_string'\tuse this password" );
    puts  ( main_shifr . localerus ?
      u8"  --пар-путь или\n  --pas-path 'путь_к_файлу_с_паролем'\t"
      u8"использовать пароль в файле" :
      "  --pas-path 'path_to_password_file'\tuse password in file" );
    puts  ( main_shifr . localerus ?
      u8"  --вход или < или \n  --input 'имя_файла'\tчитать из файла (без данной опции"
      u8" читаются данные со стандартного входа)" :
      "  --input or < 'file_name'\tread from file (without this option data reads from"
      " standard input)" ) ;
    puts  ( main_shifr . localerus ? 
      u8"  --выход или > или \n  --output 'имя_файла'\tзаписывать в файл (без данной"
      u8" опции записываются данные в стандартный выход)" :
      "  --output or > 'file_name'\twrite to file (without this option data writes to"
      " standard output)"    );
    puts  ( main_shifr . localerus ? 
      u8"  --текст или\n  --text\tшифрованный файл записан текстом ascii" :
      "  --text\tencrypted file written in ascii text"    );
    puts  ( main_shifr . localerus ? 
      u8"  --2\tиспользовать двух битное шифрование, ключ = 45 бит ( 6 - 14 букв )." :
      "  --2\tusing two bit encryption, key = 45 bits ( 6 - 14 letters )." ) ;
    puts  ( main_shifr . localerus ?
      u8"  --3\tиспользовать трёх битное шифрование, ключ = 296 бит ( 45 - 90 букв )."
      u8" ( по-умолчанию )" :
      "  --3\tusing three bit encryption, key = 296 bits ( 45 - 90 letters )."
      " ( by default )") ;
    fputs  ( main_shifr . localerus ?  
      u8"Буквы в пароле (алфавит):\n  --а95 или\n  --a95\t\'" :
      "Letters in password (alphabet):\n  --a95\t\'" , stdout ) ;
    { char const * cj = & ( main_shifr  . letters [ 0 ] ) ;
      do {
        fputc ( * cj  , stdout  ) ;
        ++ cj ;
      } while ( cj not_eq ( & ( main_shifr  . letters [ letters_count ] ) ) ) ; }
    fputs ( ( main_shifr . localerus ?
      u8"\'\n  --а62 или\n  --a62\t\'" :
      "\'\n  --a62\t\'" ) , stdout  ) ;
    { char const * cj = & ( main_shifr  . letters2 [ 0 ] ) ;
      do {
        fputc ( * cj  , stdout  ) ;
        ++ cj ;
      } while ( cj not_eq ( & ( main_shifr  . letters2 [ letters_count2 ] ) ) ) ; }
    fputs ( ( main_shifr . localerus ?
      u8"\'\t(по умолчанию)\n" :
      "\'\t(by default)\n"  ) , stdout  ) ;

    fputs ( ( main_shifr . localerus ?
      u8"  --а10 или\n  --a10\t\'" :
      "\'\n  --a10\t\'" ) , stdout  ) ;
    { char const * cj = & ( main_shifr  . letters3 [ 0 ] ) ;
      do {
        fputc ( * cj  , stdout  ) ;
        ++ cj ;
      } while ( cj not_eq ( & ( main_shifr  . letters3 [ letters_count3 ] ) ) ) ; }
    fputs ( ( main_shifr . localerus ?
      u8"\'\n" :
      "\'\n"  ) , stdout  ) ;

    puts  ( main_shifr  . localerus ?
      u8"Пример использования :"  :
      "Usage example"  ) ;
    puts  ( main_shifr  . localerus ?
      u8"  $ ./shifr --ген-пар > psw"  :
      "  $ ./shifr --gen-pas > psw"  ) ;
    puts  ( 
      "  $ cat psw\n"
      "  n3LTQH4eIicGDNaF8CDVRGdaCEVXxPPgikJ9lbQKW4zs8StkhD"  ) ;
    puts  ( main_shifr  . localerus ?
      u8"  $ ./shifr --пар-путь 'psw' > test.shi --текст"  :
      "  $ ./shifr --pas-path 'psw' > test.shi --text"  ) ;
    puts( main_shifr  . localerus ?
      u8"  2+2 (Нажимаем Enter,Ctrl+D)" :
      "  2+2 (Press Enter,Ctrl+D)" ) ;
    puts  ( 
      "  $ cat test.shi\n"
      "  ylQ?ncm;ags" ) ;
    puts( main_shifr  . localerus ?
      u8"  $ ./shifr --пар-путь 'psw' < test.shi --текст --расшифр" :
      "  $ ./shifr --pas-path 'psw' < test.shi --text --decrypt" ) ;
    puts  ( "  2+2" ) ;
    return 0 ; }
  { int argj = 1 ;
  for ( ; argv [ argj ] ; ++ argj ) {
    if ( flagreadpasswdfromfile ) {
      FILE * const f = fopen  ( argv  [ argj  ] , & ( "r" [ 0 ] ) ) ;
      if  ( f == NULL ) {
        int const e = errno ; 
        fprintf ( stderr  , ( main_shifr . localerus ?
          u8"Ошибка открытия файла \"%s\" : %s\n" :
          "Error opening file \"%s\" : %s\n" ) , argv  [ argj  ] ,
            strerror  ( e ) ) ;
        main_shifr  . string_exception  = ( main_shifr . localerus ?
          ( strcp ) & u8"Ошибка открытия файла" :
          ( strcp ) & "Error opening file" ) ;
        longjmp ( main_shifr  . jump  , 1 ) ; }
      clearerr  ( f ) ;
      size_t nr;
      size_t  ns ;
      if ( main_shifr . use_version == 2 ) {
        ns  = 30 ;
        nr = fread  ( & main_shifr  . password_letters2 , 1 , ns , f ) ; }
      else {
        ns  = 180 ;
        nr = fread  ( & main_shifr  . password_letters3 , 1 , ns , f ) ; }
      if ( nr >= ns )  {
        main_shifr  . string_exception  = ( main_shifr . localerus ?
          ( strcp ) & u8"Файл пароля очень большой" :
          ( strcp ) & "Password file is very large" ) ;
      longjmp ( main_shifr  . jump  , 1 ) ; }
      if ( ( not feof ( f ) ) and ferror ( f ) ) {
        fprintf ( stderr  , ( main_shifr . localerus ?
          u8"Ошибка чтения файла \"%s\" \n" :
          "Error reading file \"%s\" \n" ) , argv  [ argj  ] ) ;
        main_shifr  . string_exception  = ( main_shifr . localerus ?
          ( strcp ) & u8"Ошибка чтения файла" :
          ( strcp ) & "Error reading file" ) ;
        longjmp ( main_shifr  . jump  , 1 ) ; }
      char * psw_uni ;
      if ( main_shifr . use_version == 2 )
        psw_uni = main_shifr  . password_letters2 ;
      else 
        psw_uni = main_shifr  . password_letters3 ;
      psw_uni [ nr ] = '\00' ;

      switch  ( main_shifr . password_alphabet  ) {
      case  letters_count :
        { size_t i  = 0 ;
          for ( ; i < nr  ; ++  i ) {
            if (  psw_uni [ i ] < ' ' or
              psw_uni  [ i ] > '~' ) {
              psw_uni [ i ] = '\00' ;
              nr = i ;
              break ; } } }
        break ;
      case  letters_count2  :
        { size_t i  = 0 ;
          for ( ; i < nr  ; ++  i ) {
            char  psw_unii = psw_uni [ i ] ;
            if ( ( psw_unii < '0' or
                psw_unii > '9' ) and
              ( psw_unii < 'a' or
                psw_unii > 'z' ) and
              ( psw_unii < 'A' or
                psw_unii > 'Z' ) ) {
              psw_uni [ i ] = '\00' ;
              nr = i ;
              break ; } } }
        break ;
      case  letters_count3  :
        { size_t i  = 0 ;
          for ( ; i < nr  ; ++  i ) {
            if (  psw_uni [ i ] < '0' or
              psw_uni  [ i ] > '9' ) {
              psw_uni [ i ] = '\00' ;
              nr = i ;
              break ; } } }
        break ;
      default :
        main_shifr  . string_exception  = ( main_shifr  . localerus ?
          ( strcp ) & u8"неизвестный алфавит пароля" :
          ( strcp ) & "unknown password alphabet" ) ;
        longjmp ( main_shifr  . jump  , 1 ) ; }

      string_to_password  ( & main_shifr ) ;
      if ( fclose  ( f ) )  {
        int e = errno ; 
        fprintf ( stderr  , ( main_shifr . localerus ?
          u8"Ошибка закрытия файла \"%s\" : %s\n" :
          "Error closing file \"%s\" : %s\n" ) , argv  [ argj  ] ,
            strerror  ( e ) ) ;
        main_shifr  . string_exception  = ( main_shifr . localerus ?
          ( strcp ) & u8"Ошибка закрытия файла" :
          ( strcp ) & "Error closing file" ) ;
        longjmp ( main_shifr  . jump  , 1 ) ; }
      flagpasswd  = true  ; 
      flagreadpasswdfromfile = false  ; } // if flagreadpasswdfromfile
    else
    if  ( flagreadpasswd  ) {
      if  ( flagpasswd  ) {
        main_shifr  . string_exception  = ( main_shifr . localerus ?
          ( strcp ) & u8"пароль уже задан" :
          ( strcp ) & "password already set" );
        longjmp(main_shifr  . jump,1); }

      if ( main_shifr . use_version == 2 ) {
        strncpy ( main_shifr  . password_letters2 , argv  [ argj  ] ,
          password_letters2size  ) ;
        string_to_password  ( & main_shifr ) ;
# ifdef SHIFR_DEBUG
      fputs ( ( main_shifr . localerus ?
        u8"из строки во внутренний пароль = " :
        "from string to internal password = " ) , stderr ) ;
      number_princ  ( number_size2 ) ( & main_shifr . raspr2  . pass . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif      
        }
      else {
        strncpy ( main_shifr  . password_letters3 , argv  [ argj  ] ,
          password_letters3size ) ; 
        string_to_password  ( & main_shifr ) ;
# ifdef SHIFR_DEBUG                           
      fputs ( ( main_shifr . localerus ?
        u8"из строки во внутренний пароль = " :
        "from string to internal password = " ) , stderr ) ;
      number_princ  ( number_size3 ) ( & main_shifr . raspr3  . pass . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif                    
        }
      password_to_string  ( & main_shifr ) ;
# ifdef SHIFR_DEBUG
      if ( main_shifr . use_version == 3 ) {
        if  ( strcmp ( main_shifr  . password_letters3 , argv  [ argj  ] ) )  
          fprintf  ( stderr , main_shifr . localerus ?
            u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
            "Warning! Password \'%s\' is very large. Same as \'%s\'\n"
            , argv  [ argj  ] , & ( main_shifr  . password_letters3  [ 0 ] ) ) ; }
      else {
        if  ( strcmp ( main_shifr  . password_letters2 , argv  [ argj  ] ) )  
          fprintf  ( stderr , main_shifr . localerus ?
            u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
            "Warning! Password \'%s\' is very large. Same as \'%s\'\n"
            , argv  [ argj  ] , & ( main_shifr  . password_letters2  [ 0 ] ) ) ; }
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
          main_shifr  . flagtext = true  ; }
        else
        if ( strcmp ( argv[argj] , u8"--3" ) ==  0 ){ 
          main_shifr . use_version = 3 ; }
        else
        if ( strcmp ( argv[argj] , u8"--2" ) ==  0 ){ 
          main_shifr . use_version = 2 ; }
        else
        if (( strcmp ( argv[argj] , u8"--а95" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--a95" ) ==  0 )) { 
          main_shifr . password_alphabet = 95 ; }
        else
        if (( strcmp ( argv[argj] , u8"--а62" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--a62" ) ==  0 )) { 
          main_shifr . password_alphabet = 62 ; }
        else
        if (( strcmp ( argv[argj] , u8"--а10" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--a10" ) ==  0 )) { 
          main_shifr . password_alphabet = 10 ; }
        else {
          fprintf ( stderr , ( main_shifr . localerus ?
            u8"неопознанная опция : \'%s\'\n" :
            "unrecognized option : \'%s\'\n" ) , argv [ argj ] ) ;
          main_shifr  . string_exception  = ( main_shifr . localerus ?
            ( strcp ) & u8"неопознанная опция" :
            ( strcp ) & "unrecognized option" ) ;
          longjmp ( main_shifr  . jump  , 1 ) ; } } } }
  if ( flaggenpasswd ) {
    generate_password ( & main_shifr ) ;
    flagpasswd  = true  ;
# ifdef SHIFR_DEBUG    
  switch ( main_shifr . use_version ) {
  case  2 :
    fputs ( ( main_shifr . localerus ?
      u8"внутренний пароль = " :
      "internal password = " ) , stderr ) ;
    number_princ  ( number_size2 ) ( & main_shifr . raspr2  . pass . pub , stderr  ) ;
    fputs ( "\n" , stderr ) ;
    break ;
  case  3 :
    fputs ( ( main_shifr . localerus ?
      u8"внутренний пароль = " :
      "internal password = " ) , stderr ) ;
    number_princ  ( number_size3 ) ( & main_shifr . raspr3  . pass . pub , stderr  ) ;
    fputs ( "\n" , stderr ) ;
    break ;
  default :
    fprintf ( stderr , ( main_shifr . localerus ?
      u8"flaggenpasswd : неопознанная версия : \'%d\'\n" :
      "flaggenpasswd : unrecognized version : \'%d\'\n" ) , main_shifr . use_version ) ;
    main_shifr  . string_exception  = ( main_shifr . localerus ?
      ( strcp ) & u8"flaggenpasswd : неопознанная версия" :
      ( strcp ) & "flaggenpasswd : unrecognized version" ) ;
    longjmp ( main_shifr  . jump  , 1 ) ; }
# endif
    char  password_letters2 [ 20 ] ;
    char  password_letters62 [ 100 ] ;
    char  password_letters2_10 [ password_letters2size ] ;
    char  password_letters3_10 [ password_letters3size ] ;
    switch  ( main_shifr . use_version )  {
    case  2 :
      password_to_string_templ  ( number_size2 ) ( & main_shifr . raspr2  . pass . pub ,
        & main_shifr  . password_letters2 , & main_shifr . letters , letters_count ) ;
      password_to_string_templ  ( number_size2 ) ( & main_shifr . raspr2  . pass . pub ,
        & password_letters2 , & main_shifr . letters2 , letters_count2 ) ;
      password_to_string_templ  ( number_size2 ) ( & main_shifr . raspr2  . pass . pub ,
        & password_letters2_10 , & main_shifr . letters3 , letters_count3 ) ;
      break ;
    case  3 :
      password_to_string_templ  ( number_size3 ) ( & main_shifr . raspr3  . pass . pub ,
        & main_shifr  . password_letters3 , & main_shifr . letters , letters_count ) ;
      password_to_string_templ  ( number_size3 ) ( & main_shifr . raspr3  . pass . pub ,
        & password_letters62 , & main_shifr . letters2 , letters_count2 ) ;
      password_to_string_templ  ( number_size3 ) ( & main_shifr . raspr3  . pass . pub ,
        & password_letters3_10  , & main_shifr . letters3 , letters_count3 ) ;
      break ;
    default :
      fprintf ( stderr , ( main_shifr . localerus ?
        u8"показать пароль : неопознанная версия : \'%d\'\n" :
        "show password : unrecognized version : \'%d\'\n" ) ,
        main_shifr . use_version ) ;
      main_shifr  . string_exception  = ( main_shifr . localerus ?
        ( strcp ) & u8"показать пароль : неопознанная версия" :
        ( strcp ) & "show password : unrecognized version" ) ;
      longjmp ( main_shifr  . jump  , 1 ) ; }
# ifdef SHIFR_DEBUG        
    printf  ( ( main_shifr . localerus ? u8"--a95\tбуквами между кавычек = \'%s\'\n" : 
      "--a95\tby letters between quotes = \'%s\'\n"  ) ,
      & ( ( ( main_shifr . use_version == 3 ) ? main_shifr  . password_letters3 :
        main_shifr  . password_letters2 ) [ 0 ] ) ) ;
    printf  ( ( main_shifr . localerus ?
      u8"--a62\tбуквами между кавычек = \'%s\' (по-умолчанию)\n" : 
      "--a62\tby letters between quotes = \'%s\' (by default)\n"  ) ,
      & ( ( ( main_shifr . use_version == 3 ) ? password_letters62 :
        password_letters2 )  [ 0 ] ) ) ;
    printf  ( ( main_shifr . localerus ?
      u8"--a10\tцифрами между кавычек = \'%s\'\n" : 
      "--a10\tby digits between quotes = \'%s\'\n"  ) ,
      & ( ( ( main_shifr . use_version == 3 ) ? password_letters3_10 :
        password_letters2_10 )  [ 0 ] ) ) ;
    switch  ( main_shifr . use_version ) {
    case  2 :
      { number_priv_type ( number_size2 ) password2 ;

        string_to_password_templ  ( number_size2 ) ( & main_shifr ,
          ( strcp ) & main_shifr  . password_letters2 ,
          & password2 . pub , ( strcp ) & main_shifr . letters ,
          letters_count ) ; 
        fputs ( ( main_shifr . localerus ?
          u8"из строки95 во внутренний пароль = " :
          "from string95 to internal password = " ) , stderr ) ;
        number_princ  ( number_size2 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        string_to_password_templ  ( number_size2 ) ( & main_shifr ,
          ( strcp ) & password_letters2 ,
          & password2 . pub , ( strcp ) & main_shifr . letters2 ,
          letters_count2 ) ;
        fputs ( ( main_shifr . localerus ?
          u8"из строки62 во внутренний пароль = " :
          "from string62 to internal password = " ) , stderr ) ;
        number_princ  ( number_size2 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        string_to_password_templ  ( number_size2 ) ( & main_shifr ,
          ( strcp ) & password_letters2_10 ,
          & password2 . pub , ( strcp ) & main_shifr . letters3 ,
          letters_count3 ) ;
        fputs ( ( main_shifr . localerus ?
          u8"из строки10 во внутренний пароль = " :
          "from string10 to internal password = " ) , stderr ) ;
        number_princ  ( number_size2 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        }
      break ;
    case  3 :
      { number_priv_type ( number_size3 ) password2 ;

        string_to_password_templ  ( number_size3 ) ( & main_shifr ,
          ( strcp ) & main_shifr  . password_letters3 ,
          & password2 . pub , ( strcp ) & main_shifr . letters ,
          letters_count ) ; 
        fputs ( ( main_shifr . localerus ?
          u8"из строки95 во внутренний пароль = " :
          "from string95 to internal password = " ) , stderr ) ;
        number_princ  ( number_size3 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        string_to_password_templ  ( number_size3 ) ( & main_shifr ,
          ( strcp ) & password_letters62 ,
          & password2 . pub , ( strcp ) & main_shifr . letters2 ,
          letters_count2 ) ;
        fputs ( ( main_shifr . localerus ?
          u8"из строки62 во внутренний пароль = " :
          "from string62 to internal password = " ) , stderr ) ;
        number_princ  ( number_size3 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        string_to_password_templ  ( number_size3 ) ( & main_shifr ,
          ( strcp ) & password_letters3_10 ,
          & password2 . pub , ( strcp ) & main_shifr . letters3 ,
          letters_count3 ) ;
        fputs ( ( main_shifr . localerus ?
          u8"из строки10 во внутренний пароль = " :
          "from string10 to internal password = " ) , stderr ) ;
        number_princ  ( number_size3 ) ( & password2 . pub , stderr  ) ;
        fputs ( "\n" , stderr ) ;

        }
      break ;
    default :
      fprintf ( stderr  , main_shifr . localerus ?
        u8"неизвестная версия %d\n" : "unknown version %d\n"  ,
        main_shifr . use_version ) ;
      main_shifr  . string_exception  = ( main_shifr . localerus ?
        ( strcp ) & u8"неизвестная версия" :
        ( strcp ) & "unknown version" ) ;
      longjmp(main_shifr  . jump,1); }
# else
  switch  ( main_shifr . password_alphabet  ) {
  case  letters_count :
    puts  ( & ( ( ( main_shifr . use_version == 3 ) ?
      main_shifr  . password_letters3 : main_shifr  . password_letters2 ) [ 0 ] ) ) ;
    break ;
  case  letters_count2  :
    puts  ( & ( ( ( main_shifr . use_version == 3 ) ? password_letters62 :
      password_letters2 ) [ 0 ] ) ) ;
    break ;
  case  letters_count3  :
    puts  ( & ( ( ( main_shifr . use_version == 3 ) ? password_letters3_10 :
      password_letters2_10 ) [ 0 ] ) ) ;
    break ;
  default :
    main_shifr  . string_exception  = ( main_shifr . localerus ?
      ( strcp ) & u8"неизвестный алфавит пароля" :
      ( strcp ) & "unknown password alphabet" ) ;
    longjmp(main_shifr  . jump,1); }
# endif    
    if ( not flagoutputtofile )
      return  0 ;  } // if flaggenpasswd
# ifdef SHIFR_DEBUG
  if  ( flagenc and flagdec ) {
    main_shifr  . string_exception  = ( main_shifr . localerus ?
      ( strcp ) & u8"так зашифровывать или расшифровывать ?" :
      ( strcp ) & "so encrypt or decrypt ?" ) ;
    longjmp(main_shifr  . jump,1); }

  timestamp_t t0 = get_timestamp();
  
# endif // SHIFR_DEBUG
  // по-умолчанию шифруем
  // encrypted by default
  if ( not flagdec  )
    flagenc = true  ;
  if ( not flagpasswd )    {
    fputs ( ( main_shifr . localerus ? u8"введите пароль = " :
      "enter the password = " ) , stdout  ) ;
    enter_password  ( & main_shifr ) ; }
  if ( flaginputfromfile ) {
    FILE * const f = fopen  ( & ( ( * inputfilename ) [ 0 ] ) , & ( "r" [ 0 ] ) ) ;
    if  ( f == NULL ) {
      int const e = errno ; 
      fprintf ( stderr  , ( main_shifr . localerus ?
        u8"Ошибка чтения файла \"%s\" : %s\n" :
        "Error reading file \"%s\" : %s\n" ) , & ( ( * inputfilename ) [ 0 ] ) ,
            strerror  ( e ) ) ;
      main_shifr  . string_exception  = ( main_shifr . localerus ?
        ( strcp ) & u8"Ошибка чтения файла" :
        ( strcp ) & "Error reading file" ) ;
      longjmp(main_shifr  . jump,1); }
    flagclosefilefrom = true ;
    main_shifr  . filefrom = f ;    }
  if ( flagoutputtofile ) {
    FILE * const f = fopen  ( & ( ( * outputfilename  ) [ 0 ] ) , & ( "w" [ 0 ] ) ) ;
    if  ( f == NULL ) {
      int const e = errno ; 
      fprintf ( stderr  , ( main_shifr . localerus ?
        u8"Ошибка записи файла \"%s\" : %s\n" :
        "Error writing file \"%s\" : %s\n"  ) , & ( ( * outputfilename  ) [ 0 ] ) ,
        strerror  ( e ) ) ;
      main_shifr  . string_exception  = ( main_shifr . localerus ?
        ( strcp ) & u8"Ошибка записи файла" :
        ( strcp ) & "Error writing file" ) ;
      longjmp(main_shifr  . jump,1); }
    flagclosefileto = true ;
    main_shifr  . fileto  = f ;    }
  streambuf_init  ( & main_shifr . filebuffrom , main_shifr  . filefrom )  ;
  streambuf_init  ( & main_shifr . filebufto , main_shifr  . fileto )  ;
  password_load_uni ( & main_shifr ) ;
# ifdef SHIFR_DEBUG    
  if ( main_shifr . use_version == 3 )  {
    printarr  ( ( strcp ) & "shifr" , ( arrcp ) & main_shifr . shifr3 ,
      deshi_size3 , stderr  ) ;
    printarr  ( ( strcp ) & "deshi" , ( arrcp ) & main_shifr . deshi3 , deshi_size3 ,
      stderr  ) ; }
  else  {
    printarr  ( ( strcp ) & "shifr" , ( arrcp ) & main_shifr . shifr2 , deshi_size2 ,
      stderr  ) ;
    printarr  ( ( strcp ) & "deshi" , ( arrcp ) & main_shifr . deshi2 , deshi_size2 ,
      stderr  ) ; }
# endif // SHIFR_DEBUG
  if ( flagenc ) {

  if ( main_shifr . use_version == 3 )  {
    uint8_t inputbuffer [ 0x1000  ] ;
    size_t  outputbuffersize ;
    if ( main_shifr . flagtext )
      outputbuffersize  = 0x2c00  ; // 0x2b62
    else
      outputbuffersize  = 0x2100  ; // 0x2001
    uint8_t outputbuffer  [ outputbuffersize ] ;
    size_t  writecount  ;
    size_io sizeio  ;
    do  {
      size_t readcount = fread ( & (  inputbuffer [ 0 ] ) , 1 , 0x1000 ,
        main_shifr . filefrom ) ;
      if ( readcount  ) {
          sizeio  = shifr_encrypt3  ( & main_shifr ,
            ( arrcps ) { .cp = ( arrcp ) & inputbuffer , .s = readcount } ,
            ( arrps ) { .p = ( arrp ) & outputbuffer , .s = outputbuffersize } ) ;
# ifdef SHIFR_DEBUG
        if ( sizeio . i < readcount ) {
          fprintf ( stderr  , "sizeio . i = %zu , readcount = %zu\n"  , sizeio . i ,
            readcount ) ;
          main_shifr . string_exception  = ( strcp ) & "sizeio . i < readcount" ;
          longjmp ( main_shifr . jump  , 1 ) ; }
        if ( sizeio . o > outputbuffersize ) {
          fprintf ( stderr  , "sizeio . o = %zu , outputbuffersize = %zu\n"  ,
            sizeio . o , outputbuffersize ) ;
          main_shifr . string_exception  = ( strcp ) & "sizeio . o > outputbuffersize" ;
          longjmp ( main_shifr . jump  , 1 ) ; }
# endif // SHIFR_DEBUG
        writecount = fwrite ( & ( outputbuffer [ 0 ] ) , sizeio . o , 1 ,
          main_shifr . fileto ) ;
        if ( writecount == 0 ) {
          main_shifr . string_exception  = ( main_shifr . localerus ?
            ( strcp ) & u8"v3:ошибка записи в файл" :
            ( strcp ) & "v3:error writing to file" ) ;
          longjmp ( main_shifr . jump  , 1 ) ; }
        if ( feof ( main_shifr . filefrom ) )
          break ; }
      else {
        if ( ferror ( main_shifr . filefrom ) ) {
          main_shifr . string_exception  = ( main_shifr . localerus ?
            ( strcp ) & u8"ошибка чтения файла" :
            ( strcp ) & "error reading the file" ) ;
          longjmp ( main_shifr . jump  , 1 ) ; }
        break ; }
    } while ( true ) ;      
      { uint8_t bytes = streambuf_writeflushzero3 ( & main_shifr ,
          ( arrps ) { .p = ( arrp ) & outputbuffer , .s = outputbuffersize } ) ;
        if ( bytes ) {
          writecount = fwrite ( & ( outputbuffer [ 0 ] ) , bytes , 1 ,
            main_shifr . fileto ) ;
          if ( writecount == 0 ) {
            main_shifr . string_exception  = ( main_shifr . localerus ?
              ( strcp ) & u8"v3:ошибка записи в файл ( writecount == 0 )" :
              ( strcp ) & "v3:error writing to file ( writecount == 0 )" ) ;
            longjmp ( main_shifr . jump  , 1 ) ; } } } } // use_version == 3
    else
    if ( main_shifr . use_version == 2 )  {
    uint8_t inputbuffer [ 0x1000  ] ;
    size_t  outputbuffersize ;
    if ( main_shifr . flagtext )
      outputbuffersize  = 0x3100  ; // 0x30cd
    else
      outputbuffersize  = 0x2100  ; // 0x2000
    uint8_t outputbuffer  [ outputbuffersize ] ;
    size_t  writecount  ;
    size_io sizeio  ;
    do  {
      size_t readcount = fread ( & (  inputbuffer [ 0 ] ) , 1 , 0x1000 ,
        main_shifr . filefrom ) ;
      if ( readcount  ) {
          sizeio  = shifr_encrypt2  ( & main_shifr ,
            ( arrcps ) { .cp = ( arrcp ) & inputbuffer , .s = readcount } ,
            ( arrps ) { .p = ( arrp ) & outputbuffer , .s = outputbuffersize } ) ;
# ifdef SHIFR_DEBUG
        if ( sizeio . i < readcount ) {
          fprintf ( stderr  , "sizeio . i = %zu , readcount = %zu\n"  , sizeio . i ,
            readcount ) ;
          main_shifr . string_exception  = ( strcp ) & "sizeio . i < readcount" ;
          longjmp ( main_shifr . jump  , 1 ) ; }
# endif // SHIFR_DEBUG
        writecount = fwrite ( & ( outputbuffer [ 0 ] ) , sizeio . o , 1 ,
          main_shifr . fileto ) ;
        if ( writecount == 0 )
          goto Exc ;
        if ( feof ( main_shifr . filefrom ) )
          break ; }
      else {
        if ( ferror ( main_shifr . filefrom ) ) {
          main_shifr . string_exception  = ( main_shifr . localerus ?
            ( strcp ) & u8"ошибка чтения файла" :
            ( strcp ) & "error reading the file" ) ;
          longjmp ( main_shifr . jump  , 1 ) ; }
        break ; }
    } while ( true ) ;
    size_t sizeout  ;
      sizeout = shifr_encrypt2_flush  ( & main_shifr ,
        ( arrps ) { .p = ( arrp ) & outputbuffer , .s = outputbuffersize }  ) ;
    if  ( sizeout ) {
      writecount = fwrite ( & ( outputbuffer [ 0 ] ) , sizeout , 1 ,
        main_shifr . fileto ) ;
      if ( writecount == 0 ) {
Exc :
        main_shifr . string_exception  = ( main_shifr . localerus ?
          ( strcp ) & u8"ошибка записи в файл" :
          ( strcp ) & "error writing to file" ) ;
        longjmp ( main_shifr . jump  , 1 ) ; } } } // use_version == 2
    } // if flagenc
  else { // flagdec
    if ( main_shifr . use_version == 2 )  {
      uint8_t inputbuffer [ 0x1000  ] ;
      size_t  outputbuffersize ;
      if ( main_shifr . flagtext )
        outputbuffersize  = 0x560  ; // 0x556
      else
        outputbuffersize  = 0x810  ; // 0x800
      uint8_t outputbuffer  [ outputbuffersize ] ;
      size_t  writecount  ;
      size_io sizeio  ;
      do  {
        size_t readcount = fread ( & (  inputbuffer [ 0 ] ) , 1 , 0x1000 ,
          main_shifr . filefrom ) ;
        if ( readcount  ) {
          sizeio  = shifr_decrypt2  ( & main_shifr ,
            ( arrcps ) { .cp = ( arrcp ) & inputbuffer , .s = readcount } ,
            ( arrps ) { .p = ( arrp ) & outputbuffer , .s = outputbuffersize } ) ;
# ifdef SHIFR_DEBUG
          if ( sizeio . i < readcount ) {
            fprintf ( stderr  , "sizeio . i = %zu , readcount = %zu\n"  , sizeio . i ,
              readcount ) ;
            main_shifr . string_exception  = ( strcp ) & "sizeio . i < readcount" ;
            longjmp ( main_shifr . jump  , 1 ) ; }
# endif // SHIFR_DEBUG
          writecount = fwrite ( & ( outputbuffer [ 0 ] ) , sizeio . o , 1 ,
            main_shifr . fileto ) ;
          if ( writecount == 0 ) {
            main_shifr . string_exception  = ( main_shifr . localerus ?
              ( strcp ) & u8"ошибка записи в файл" :
              ( strcp ) & "error writing to file" ) ;
            longjmp ( main_shifr . jump  , 1 ) ; }
          if ( feof ( main_shifr . filefrom ) )
            break ; } // if readcount
        else {
          if ( ferror ( main_shifr . filefrom ) ) {
            main_shifr . string_exception  = ( main_shifr . localerus ?
              ( strcp ) & u8"ошибка чтения файла" :
              ( strcp ) & "error reading the file" ) ;
            longjmp ( main_shifr . jump  , 1 ) ; }
          break ; }
      } while ( true ) ; } // ver 2
    else {
      uint8_t inputbuffer [ 0x1000  ] ;
      size_t  outputbuffersize ;
      if ( main_shifr . flagtext )
        outputbuffersize  = 0x610  ; // 0x600
      else
        outputbuffersize  = 0x810  ; // 0x7ff
      uint8_t outputbuffer  [ outputbuffersize ] ;
      size_t  writecount  ;
      size_io sizeio  ;
      do  {
        size_t readcount = fread ( & (  inputbuffer [ 0 ] ) , 1 , 0x1000 ,
          main_shifr . filefrom ) ;
        if ( readcount  ) {
          sizeio  = shifr_decrypt3  ( & main_shifr ,
            ( arrcps  ) { . cp  = ( arrcp ) & inputbuffer , . s = readcount } ,
            ( arrps ) { . p = ( arrp  ) & outputbuffer , . s = outputbuffersize } ) ;
# ifdef SHIFR_DEBUG
          if ( sizeio . i < readcount ) {
            fprintf ( stderr  , "sizeio . i = %zu , readcount = %zu\n"  , sizeio . i ,
              readcount ) ;
            main_shifr . string_exception  = ( strcp ) & "sizeio . i < readcount" ;
            longjmp ( main_shifr . jump  , 1 ) ; }
# endif // SHIFR_DEBUG
          writecount = fwrite ( & ( outputbuffer [ 0 ] ) , sizeio . o , 1 ,
            main_shifr . fileto ) ;
          if ( writecount == 0 ) {
            main_shifr . string_exception  = ( main_shifr . localerus ?
              ( strcp ) & u8"ошибка записи в файл" :
              ( strcp ) & "error writing to file" ) ;
            longjmp ( main_shifr . jump  , 1 ) ; }
          if ( feof ( main_shifr . filefrom ) )
            break ; } // if readcount
        else {
          if ( ferror ( main_shifr . filefrom ) ) {
            main_shifr . string_exception  = ( main_shifr . localerus ?
              ( strcp ) & u8"ошибка чтения файла" :
              ( strcp ) & "error reading the file" ) ;
            longjmp ( main_shifr . jump  , 1 ) ; }
          break ; }
      } while ( true ) ; } }
  int resulterror  = 0 ;
  if ( flagclosefileto  ) {
    if  ( fclose  ( main_shifr  . fileto  ) ) {
      int const e = errno ;
      fprintf  (  stderr, ( main_shifr . localerus ?
        u8"Ошибка закрытия файла записи \"%s\" : %s\n" :
        "Error closing file to writing \"%s\" : %s\n" ) ,
        & ( ( * outputfilename ) [ 0 ] ) , strerror  ( e ) ) ;
      resulterror = 1 ; } }
  if ( flagclosefilefrom ) {
    if  ( ( not feof ( main_shifr  . filefrom ) ) and 
      fclose  ( main_shifr  . filefrom ) ) {
      int const e = errno ; 
      fprintf ( stderr  , ( main_shifr . localerus ?
        u8"Ошибка закрытия файла чтения \"%s\" : %s\n" :
        "Error closing file of reading \"%s\" : %s\n" ) ,
        & ( ( * inputfilename ) [ 0 ] ) , strerror  ( e ) ) ;
      resulterror = 2 ; } }
# ifdef SHIFR_DEBUG
    timestamp_t t1 = get_timestamp();
    long  double secs = (t1 - t0) / 1000000.0L;      
  fprintf ( stderr  , ( main_shifr . localerus ?  u8"время = %Lf сек\n" :
    "time = %Lf sec\n" ) , secs  ) ;
# endif // SHIFR_DEBUG
  return  resulterror ; }
