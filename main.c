# include "shifr.h"
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
  shifr_init  ( ) ;
  if  ( argc  <=  1  ) {
    puts ( ns_shifr . localerus ?
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
      u8"  --вход или < или \n  --input 'имя_файла'\tчитать из файла (без данной опции читаются данные со стандартного входа)" :
      "  --input or < 'file_name'\tread from file (without this option data reads from standard input)");
    puts  (ns_shifr . localerus ? 
      u8"  --выход или > или \n  --output 'имя_файла'\tзаписывать в файл (без данной опции записываются данные в стандартный выход)" :
      "  --output or > 'file_name'\twrite to file (without this option data writes to standard output)"    );
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
    puts  ( ns_shifr  . localerus ? u8"  $ ./shifr --ген-пар > psw"  :
      "  $ ./shifr --gen-pas > psw"  ) ;
    puts  ( 
      "  $ cat psw\n"
      "  n3LTQH4eIicGDNaF8CDVRGdaCEVXxPPgikJ9lbQKW4zs8StkhD"  ) ;
    puts  ( ns_shifr  . localerus ?
      u8"  $ ./shifr --пар-путь 'psw' > test.shi --текст"  :
      "  $ ./shifr --pas-path 'psw' > test.shi --text"  ) ;
    puts( ns_shifr  . localerus ? u8"  2+2 (Нажимаем Enter,Ctrl+D)" :
      "  2+2 (Press Enter,Ctrl+D)" ) ;
    puts  ( 
      "  $ cat test.shi\n"
      "  ylQ?ncm;ags" ) ;
    puts( ns_shifr  . localerus ?
      u8"  $ ./shifr --пар-путь 'psw' < test.shi --текст --расшифр" :
      "  $ ./shifr --pas-path 'psw' < test.shi --text --decrypt" ) ;
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
        ( strcp ) & u8"Ошибка открытия файла" :
        ( strcp ) & "Error opening file" ) ;
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
        ( strcp ) & u8"Файл пароля очень большой" :
        ( strcp ) & "Password file is very large" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; }
    if ( ( not feof ( f ) ) and ferror ( f ) ) {
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка чтения файла \"%s\" \n" :
        "Error reading file \"%s\" \n" ) , argv  [ argj  ] ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( strcp ) & u8"Ошибка чтения файла" :
        ( strcp ) & "Error reading file" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; }

  char * psw_uni ;
  if ( ns_shifr . use_version == 4 ) 
    psw_uni = password_letters ;
  else
    psw_uni = password_letters6 ;
  psw_uni [ nr ] = '\00' ;

      if ( ns_shifr . password_alphabet == 95 )  {
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
      if ( ns_shifr . password_alphabet == 95 )
        string_to_password_templ  ( 6 ) ( & password_letters ,
          & ns_shifr . raspr4  . pass ,
          & ns_shifr . letters ,  letters_count ) ;
      else
        string_to_password_templ  ( 6 ) ( & password_letters ,
          & ns_shifr . raspr4  . pass ,
          & ns_shifr . letters2 , letters_count2 ) ;
      break ;
    case 6 : {
      if ( ns_shifr . password_alphabet == 95 )
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
        ( strcp ) & u8"версия не поддерживается" :
        ( strcp ) & "version is not supported" ) ;
      longjmp(ns_shifr  . jump,1); }
    if ( fclose  ( f ) )  {
      int e = errno ; 
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка закрытия файла \"%s\" : %s\n" :
        "Error closing file \"%s\" : %s\n" ) , argv  [ argj  ] ,
            strerror  ( e ) ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( strcp ) & u8"Ошибка закрытия файла" :
        ( strcp ) & "Error closing file" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; }
    flagpasswd  = true  ; 
    flagreadpasswdfromfile = false  ; }
    else
    if  ( flagreadpasswd  ) {
      if  ( flagpasswd  ) {
        ns_shifr  . string_exception  = ( ns_shifr . localerus ?
          ( strcp ) & u8"пароль уже задан" :
          ( strcp ) & "password already set" );
        longjmp(ns_shifr  . jump,1); }
      if ( ns_shifr . use_version == 4 ) {
        if ( ns_shifr . password_alphabet == 95 )
          string_to_password_templ  ( 6 ) ( ( strcp ) ( argv  [ argj  ] ) ,
            & ns_shifr . raspr4  . pass , & ns_shifr . letters ,
            letters_count ) ; 
        else
          string_to_password_templ  ( 6 ) ( ( strcp ) ( argv  [ argj  ] ) ,
            & ns_shifr . raspr4  . pass , & ns_shifr . letters2 ,
            letters_count2 ) ;
# ifdef SHIFR_DEBUG
      fputs ( ( ns_shifr . localerus ?
        u8"из строки во внутренний пароль = " :
        "from string to internal password = " ) , stderr ) ;
      number_princ  ( 6 ) ( & ns_shifr . raspr4  . pass , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif                           
        }
      if ( ns_shifr . use_version == 6 ) {
        if ( ns_shifr . password_alphabet == 95 )
          string_to_password6_uni ( (char(*)[])(argv[argj]) ,
            & ns_shifr . raspr6  . password_const , & ns_shifr . letters ,
            letters_count ) ;
        else
          string_to_password6_uni ( (char(*)[])(argv[argj]) ,
            & ns_shifr . raspr6  . password_const , & ns_shifr . letters2 ,
            letters_count2 ) ; 
# ifdef SHIFR_DEBUG                           
        { t_number320 password6 ;
          if ( ns_shifr . password_alphabet == 95 )
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
        if ( ns_shifr . password_alphabet == 95 )
          password_to_string_templ  ( 6 ) ( & ns_shifr . raspr4  . pass ,
            & password_letters , & ns_shifr . letters , letters_count ) ;
        else
          password_to_string_templ  ( 6 ) ( & ns_shifr . raspr4  . pass ,
            & password_letters , & ns_shifr . letters2 , letters_count2 ) ; }
      if ( ns_shifr . use_version == 6 ) {
        if ( ns_shifr . password_alphabet == 95 )
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
          ns_shifr . password_alphabet = 95 ; }
        else
        if (( strcmp ( argv[argj] , u8"--а62" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--a62" ) ==  0 )) { 
          ns_shifr . password_alphabet = 62 ; }
        else {
          fprintf ( stderr , ( ns_shifr . localerus ?
            u8"неопознанная опция : \'%s\'\n" :
            "unrecognized option : \'%s\'\n" ) , argv [ argj ] ) ;
          ns_shifr  . string_exception  = ( ns_shifr . localerus ?
            ( strcp ) & u8"неопознанная опция" :
            ( strcp ) & "unrecognized option" ) ;
          longjmp(ns_shifr  . jump,1); } } }
  if ( flaggenpasswd ) {
    switch  ( ns_shifr . use_version  ) {
    case  4 : 
      shifr_generate_pass4  ( ) ;
      shifr_pass_to_array4  ( ) ;
# ifdef SHIFR_DEBUG
      fputs ( ( ns_shifr . localerus ?
        u8"внутренний пароль = " :
        "internal password = " ) , stderr ) ;
      number_princ  ( 6 ) ( & ns_shifr . raspr4  . pass , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif
      break ;
    case 6 :
      shifr_password_generate6 ( ) ;
      break ;
    default :
      fprintf ( stderr , ( ns_shifr . localerus ?
        u8"неопознанная версия : \'%d\'\n" :
        "unrecognized version : \'%d\'\n" ) , ns_shifr . use_version ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( strcp ) & u8"неопознанная версия" :
        ( strcp ) & "unrecognized version" ) ;
      longjmp ( ns_shifr  . jump  , 1 ) ; }
  flagpasswd  = true  ;
# ifdef SHIFR_DEBUG    
  switch ( ns_shifr . use_version ) {
  case  4 :
    fputs ( ( ns_shifr . localerus ?
      u8"внутренний пароль = " :
      "internal password = " ) , stderr ) ;
    number_princ  ( 6 ) ( & ns_shifr . raspr4  . pass , stderr  ) ;
    fputs ( "\n" , stderr ) ;
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
      ( strcp ) & u8"неопознанная версия" :
      ( strcp ) & "unrecognized version" ) ;
    longjmp ( ns_shifr  . jump  , 1 ) ; }
# endif
    char  password_letters [ 20 ] ;
    char  password_letters2 [ 20 ] ;
    char  password_letters61 [ 100 ] ;
    char  password_letters62 [ 100 ] ;
    switch  ( ns_shifr . use_version )  {
    case  4 :
      password_to_string_templ  ( 6 ) ( & ns_shifr . raspr4  . pass ,
        & password_letters , & ns_shifr . letters , letters_count ) ;
      password_to_string_templ  ( 6 ) ( & ns_shifr . raspr4  . pass ,
        & password_letters2 , & ns_shifr . letters2 , letters_count2 ) ; 
      break ;
    case  6 :
      password_to_string6_uni ( & ns_shifr . raspr6  . password_const ,
        & password_letters61 , & ns_shifr . letters , letters_count ) ;
      password_to_string6_uni ( & ns_shifr . raspr6  . password_const ,
        & password_letters62 , & ns_shifr . letters2 , letters_count2 ) ;
      break ;
    default :
      fprintf ( stderr , ( ns_shifr . localerus ?
        u8"неопознанная версия : \'%d\'\n" :
        "unrecognized version : \'%d\'\n" ) , ns_shifr . use_version ) ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( strcp ) & u8"неопознанная версия" :
        ( strcp ) & "unrecognized version" ) ;
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
      { number_type ( 6 ) password2 ;
        string_to_password_templ  ( 6 ) ( & password_letters ,
          & password2 , & ns_shifr . letters ,
          letters_count ) ; 
        fputs ( ( ns_shifr . localerus ?
          u8"из строки95 во внутренний пароль = " :
          "from string95 to internal password = " ) , stderr ) ;
        number_princ  ( 6 ) ( & password2 , stderr  ) ;
        fputs ( "\n" , stderr ) ;
        string_to_password_templ  ( 6 ) ( & password_letters2 ,
          & password2 , & ns_shifr . letters2 ,
          letters_count2 ) ;
        fputs ( ( ns_shifr . localerus ?
          u8"из строки62 во внутренний пароль = " :
          "from string62 to internal password = " ) , stderr ) ;
        number_princ  ( 6 ) ( & password2 , stderr  ) ;
        fputs ( "\n" , stderr ) ;  }
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
        ( strcp ) & u8"неизвестная версия" :
        ( strcp ) & "unknown version" ) ;
      longjmp(ns_shifr  . jump,1); }
# else
  if ( ns_shifr . password_alphabet == 95 )
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
      ( strcp ) & u8"так зашифровывать или расшифровывать ?" :
      ( strcp ) & "so encrypt or decrypt ?" ) ;
    longjmp(ns_shifr  . jump,1); }
# endif
  //  по-умолчанию шифруем
  // encrypted by default
  if ( not flagdec  ) flagenc = true  ;
  if ( not flagpasswd )    {
    fputs ( ( ns_shifr . localerus ? u8"введите пароль = " :
      "enter the password = " ) , stdout  ) ;
    switch ( ns_shifr . use_version ) {
    case  6 :
      enter_password6  ( ) ;
      break ;
    case 4 :
      enter_password4  ( ) ;
      break ;
    default :
      fprintf(stderr,( ns_shifr . localerus ?
        u8"Неизвестная версия %d\n" :
        "Unknown version %d\n" ),ns_shifr . use_version);
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( strcp ) & u8"Неизвестная версия" :
        ( strcp ) & "Unknown version" ) ;
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
        ( strcp ) & u8"Ошибка чтения файла" :
        ( strcp ) & "Error reading file" ) ;
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
        ( strcp ) & u8"Ошибка записи файла" :
        ( strcp ) & "Error writing file" ) ;
      longjmp(ns_shifr  . jump,1); }
    flagclosefileto = true ;
    ns_shifr  . fileto  = f ;    }
  streambuf_init  ( & shifr_filebuffrom , ns_shifr  . filefrom )  ;
  streambuf_init  ( & shifr_filebufto , ns_shifr  . fileto )  ;
    switch ( ns_shifr . use_version )  {
    case 4 :
      password_load ( 6 ) ( & ns_shifr . raspr4  . pass , & ns_shifr  . shifr ,
        & ns_shifr  . deshi ) ;
      break ;
    case 6 :
      password_load6 ( & ns_shifr . raspr6  . password_const  ,
        & ns_shifr  . shifr6 , & ns_shifr  . deshi6 ) ;
      break ;
    default :
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"версия %d не поддерживается\n" :
        "version %d is not supported" ) , ns_shifr . use_version )  ;
      ns_shifr  . string_exception  = ( ns_shifr . localerus ?
        ( strcp ) & u8"версия не поддерживается" :
        ( strcp ) & "version is not supported" ) ;
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
    if  ( ( not feof ( ns_shifr  . filefrom ) ) and 
      fclose  ( ns_shifr  . filefrom ) ) {
      int const e = errno ; 
      fprintf ( stderr  , ( ns_shifr . localerus ?
        u8"Ошибка закрытия файла чтения \"%s\" : %s\n" :
        "Error closing file of reading \"%s\" : %s\n" ) ,
        & ( ( * inputfilename ) [ 0 ] ) , strerror  ( e ) ) ;
      resulterror = 2 ; } }
  return  resulterror ; }
