// Шифр ©2020 Глебов А.Н.
// Shifr ©2020 Glebe A.N.

# include <locale.h>
# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <errno.h>
# include "define.h"
# include "inline.h"

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
      u8"Шифр ©2020 Глебов А.Н.\n"
      u8"Симметричное поточное шифрование с 'солью'.\n"
      u8"'Соль' генерируется постоянно, что даёт хорошую стойкость.\n"
      u8"Размер данных увеличивается в два раза. В три раза в текстовом режиме.\n"
      u8"Нет диагностики неправильного пароля.\n"
      u8"Синтаксис : shifr [параметры]" :
      "Shifr ©2020 Glebe A.N.\n"
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
      u8"  --пар-путь или\n  --pas-path 'путь_к_файлу_с_паролем'\tиспользовать пароль в файле" :
      "  --pas-path 'path_to_password_file'\tuse password in file" );
    puts  ( main_shifr . localerus ?
      u8"  --вход или < или \n  --input 'имя_файла'\tчитать из файла (без данной опции читаются данные со стандартного входа)" :
      "  --input or < 'file_name'\tread from file (without this option data reads from standard input)" ) ;
    puts  ( main_shifr . localerus ? 
      u8"  --выход или > или \n  --output 'имя_файла'\tзаписывать в файл (без данной опции записываются данные в стандартный выход)" :
      "  --output or > 'file_name'\twrite to file (without this option data writes to standard output)"    );
    puts  ( main_shifr . localerus ? 
      u8"  --текст или\n  --text\tшифрованный файл записан текстом ascii" :
      "  --text\tencrypted file written in ascii text"    );
    puts  ( main_shifr . localerus ? 
      u8"  --4\tиспользовать четырёх битное шифрование, ключ = 45 бит ( шесть-восемь букв )." :
      "  --4\tusing four bit encryption, key = 45 bits ( six-eight letters )." ) ;
    puts  ( main_shifr . localerus ?
      u8"  --6\tиспользовать шести битное шифрование, ключ = 296 бит ( 45 - 50 букв ). ( по-умолчанию )" :
      "  --6\tusing six bit encryption, key = 296 bits ( 45 - 50 letters ). ( by default )") ;
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
  srand ( time  ( 0 ) ) ;
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
      if ( main_shifr . use_version == 4 ) {
        ns  = 20 ;
        nr = fread  ( & main_shifr  . password_letters2 , 1 , ns , f ) ; }
      else {
        ns  = 100 ;
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
      if ( main_shifr . use_version == 4 )
        psw_uni = main_shifr  . password_letters2 ;
      else 
        psw_uni = main_shifr  . password_letters3 ;
      psw_uni [ nr ] = '\00' ;
      if ( main_shifr . password_alphabet == 95 )  {
        size_t i  = 0 ;
        for ( ; i < nr  ; ++  i ) {
          if (  psw_uni [ i ] < ' ' or
            psw_uni  [ i ] > '~' ) {
            psw_uni [ i ] = '\00' ;
            nr = i ;
            break ; } } }
        else {
          size_t i  = 0 ;
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

      if ( main_shifr . use_version == 4 ) {
        strncpy ( main_shifr  . password_letters2 , argv  [ argj  ] , 20  ) ;
        string_to_password  ( & main_shifr ) ;
# ifdef SHIFR_DEBUG
      fputs ( ( main_shifr . localerus ?
        u8"из строки во внутренний пароль = " :
        "from string to internal password = " ) , stderr ) ;
      number_princ  ( number_size2 ) ( & main_shifr . raspr4  . pass , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif      
        }
      else {
        strncpy ( main_shifr  . password_letters3 , argv  [ argj  ] , 100 ) ; 
        string_to_password  ( & main_shifr ) ;
# ifdef SHIFR_DEBUG                           
      fputs ( ( main_shifr . localerus ?
        u8"из строки во внутренний пароль = " :
        "from string to internal password = " ) , stderr ) ;
      number_princ  ( number_size3 ) ( & main_shifr . raspr6  . pass , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif                    
        }
      password_to_string  ( & main_shifr ) ;
# ifdef SHIFR_DEBUG
      if ( main_shifr . use_version == 6 ) {
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
        if ( strcmp ( argv[argj] , u8"--4" ) ==  0 ){ 
          main_shifr . use_version = 4 ; }
        else
        if ( strcmp ( argv  [ argj  ] , u8"--6" ) ==  0 ) { 
          main_shifr . use_version = 6 ; }
        else
        if (( strcmp ( argv[argj] , u8"--а95" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--a95" ) ==  0 )) { 
          main_shifr . password_alphabet = 95 ; }
        else
        if (( strcmp ( argv[argj] , u8"--а62" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--a62" ) ==  0 )) { 
          main_shifr . password_alphabet = 62 ; }
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
  case  4 :
    fputs ( ( main_shifr . localerus ?
      u8"внутренний пароль = " :
      "internal password = " ) , stderr ) ;
    number_princ  ( number_size2 ) ( & main_shifr . raspr4  . pass , stderr  ) ;
    fputs ( "\n" , stderr ) ;
    break ;
  case  6 :
    fputs ( ( main_shifr . localerus ?
      u8"внутренний пароль = " :
      "internal password = " ) , stderr ) ;
    number_princ  ( number_size3 ) ( & main_shifr . raspr6  . pass , stderr  ) ;
    fputs ( "\n" , stderr ) ;
    break ;
  default :
    fprintf ( stderr , ( main_shifr . localerus ?
      u8"неопознанная версия : \'%d\'\n" :
      "unrecognized version : \'%d\'\n" ) , main_shifr . use_version ) ;
    main_shifr  . string_exception  = ( main_shifr . localerus ?
      ( strcp ) & u8"неопознанная версия" :
      ( strcp ) & "unrecognized version" ) ;
    longjmp ( main_shifr  . jump  , 1 ) ; }
# endif
    char  password_letters2 [ 20 ] ;
    char  password_letters62 [ 100 ] ;
    switch  ( main_shifr . use_version )  {
    case  4 :
      password_to_string_templ  ( number_size2 ) ( & main_shifr . raspr4  . pass ,
        & main_shifr  . password_letters2 , & main_shifr . letters , letters_count ) ;
      password_to_string_templ  ( number_size2 ) ( & main_shifr . raspr4  . pass ,
        & password_letters2 , & main_shifr . letters2 , letters_count2 ) ; 
      break ;
    case  6 :
      password_to_string_templ  ( number_size3 ) ( & main_shifr . raspr6  . pass ,
        & main_shifr  . password_letters3 , & main_shifr . letters , letters_count ) ;
      password_to_string_templ  ( number_size3 ) ( & main_shifr . raspr6  . pass ,
        & password_letters62 , & main_shifr . letters2 , letters_count2 ) ; 
      break ;
    default :
      fprintf ( stderr , ( main_shifr . localerus ?
        u8"неопознанная версия : \'%d\'\n" :
        "unrecognized version : \'%d\'\n" ) , main_shifr . use_version ) ;
      main_shifr  . string_exception  = ( main_shifr . localerus ?
        ( strcp ) & u8"неопознанная версия" :
        ( strcp ) & "unrecognized version" ) ;
      longjmp ( main_shifr  . jump  , 1 ) ; }
# ifdef SHIFR_DEBUG        
    printf  ( ( main_shifr . localerus ? u8"--a95\tбуквами между кавычек = \'%s\'\n" : 
      "--a95\tby letters between quotes = \'%s\'\n"  ) ,
      & ( ( ( main_shifr . use_version == 6 ) ? main_shifr  . password_letters3 :
        main_shifr  . password_letters2 ) [ 0 ] ) ) ;
    printf  ( ( main_shifr . localerus ?
      u8"--a62\tбуквами между кавычек = \'%s\' (по-умолчанию)\n" : 
      "--a62\tby letters between quotes = \'%s\' (by default)\n"  ) ,
      & ( ( ( main_shifr . use_version == 6 ) ? password_letters62 :
        password_letters2 )  [ 0 ] ) ) ;
    switch  ( main_shifr . use_version ) {
    case  4 :
      { number_type ( number_size2 ) password2 ;
        string_to_password_templ  ( number_size2 ) ( & main_shifr ,
          ( strcp ) & main_shifr  . password_letters2 ,
          & password2 , ( strcp ) & main_shifr . letters ,
          letters_count ) ; 
        fputs ( ( main_shifr . localerus ?
          u8"из строки95 во внутренний пароль = " :
          "from string95 to internal password = " ) , stderr ) ;
        number_princ  ( number_size2 ) ( & password2 , stderr  ) ;
        fputs ( "\n" , stderr ) ;
        string_to_password_templ  ( number_size2 ) ( & main_shifr ,
          ( strcp ) & password_letters2 ,
          & password2 , ( strcp ) & main_shifr . letters2 ,
          letters_count2 ) ;
        fputs ( ( main_shifr . localerus ?
          u8"из строки62 во внутренний пароль = " :
          "from string62 to internal password = " ) , stderr ) ;
        number_princ  ( number_size2 ) ( & password2 , stderr  ) ;
        fputs ( "\n" , stderr ) ;  }
      break ;
    case  6 :
      { number_type ( number_size3 ) password2 ;
        string_to_password_templ  ( number_size3 ) ( & main_shifr ,
          ( strcp ) & main_shifr  . password_letters3 ,
          & password2 , ( strcp ) & main_shifr . letters ,
          letters_count ) ; 
        fputs ( ( main_shifr . localerus ?
          u8"из строки95 во внутренний пароль = " :
          "from string95 to internal password = " ) , stderr ) ;
        number_princ  ( number_size3 ) ( & password2 , stderr  ) ;
        fputs ( "\n" , stderr ) ;
        string_to_password_templ  ( number_size3 ) ( & main_shifr ,
          ( strcp ) & password_letters62 ,
          & password2 , ( strcp ) & main_shifr . letters2 ,
          letters_count2 ) ;
        fputs ( ( main_shifr . localerus ?
          u8"из строки62 во внутренний пароль = " :
          "from string62 to internal password = " ) , stderr ) ;
        number_princ  ( number_size3 ) ( & password2 , stderr  ) ;
        fputs ( "\n" , stderr ) ;  }
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
  if ( main_shifr . password_alphabet == 95 )
    puts  ( & ( ( ( main_shifr . use_version == 6 ) ?
      main_shifr  . password_letters3 : main_shifr  . password_letters2 ) [ 0 ] ) ) ;
  else
    puts  ( & ( ( ( main_shifr . use_version == 6 ) ? password_letters62 :
      password_letters2 ) [ 0 ] ) ) ;
# endif    
    if ( not flagoutputtofile ) return  0 ;  }
# ifdef SHIFR_DEBUG        
  if  ( flagenc and flagdec ) {
    main_shifr  . string_exception  = ( main_shifr . localerus ?
      ( strcp ) & u8"так зашифровывать или расшифровывать ?" :
      ( strcp ) & "so encrypt or decrypt ?" ) ;
    longjmp(main_shifr  . jump,1); }
# endif
  //  по-умолчанию шифруем
  // encrypted by default
  if ( not flagdec  ) flagenc = true  ;
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
  if ( main_shifr . use_version == 6 )  { 
    printarr  ( ( strcp ) & "shifr" , ( arrcp ) & main_shifr . shifr6 ,
      deshi_size6 , stderr  ) ;
    printarr  ( ( strcp ) & "deshi" , ( arrcp ) & main_shifr . deshi6 , deshi_size6 ,
      stderr  ) ; }
  else  {
    printarr  ( ( strcp ) & "shifr" , ( arrcp ) & main_shifr . shifr , deshi_size2 ,
      stderr  ) ;
    printarr  ( ( strcp ) & "deshi" , ( arrcp ) & main_shifr . deshi , deshi_size2 ,
      stderr  ) ; }
# endif // SHIFR_DEBUG
  if ( flagenc ) {
    if ( main_shifr . use_version == 4 )  {
      uint8_t inputbuffer [ 0x1000  ] ;
      size_t  outputbuffersize ;
      if ( main_shifr . flagtext )
        outputbuffersize  = 0x3100  ;
      else
        outputbuffersize  = 0x2100  ;
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
          longjmp ( main_shifr . jump  , 1 ) ; } } }
    else
      shifr_encrypt6 ( & main_shifr  ) ; }
  else {/*
    if ( main_shifr . use_version == 4 )  {
      uint8_t inputbuffer [ 0x1000  ] ;
      size_t  outputbuffersize ;
      if ( main_shifr . flagtext )
        outputbuffersize  = 0x555 ;
      else
        outputbuffersize  = 0x800  ;
      uint8_t outputbuffer  [ outputbuffersize ] ;
      size_t  writecount  ;
      size_t sizeout  ;
      sizeout = shifr_decrypt2  ( & main_shifr , ( arrcp ) & inputbuffer  ,
        readcount , & outputbuffer ) ;
...
      }
    else*/
      shifr_decrypt ( & main_shifr ) ; }
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
  return  resulterror ; }
