// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# include <locale.h>
# include <errno.h>
# include "define.h"
# include "inline.h"

# define  streambuf_init  shifr_streambuf_init
# define  enter_password  shifr_enter_password
# ifdef SHIFR_DEBUG
typedef shifr_timestamp_t timestamp_t ;
# endif
# define  show_help shifr_show_help
# define  main_genpsw shifr_main_genpsw
# define  test_password shifr_test_password
typedef shifr_strcp strcp ;
typedef shifr_arrcp arrcp ;
    
int main  ( int argc , char * argv [ ] ) {
  t_ns_shifr  main_shifr  ;
  shifr_init  ( & main_shifr ) ;
  char const * const locale = setlocale ( LC_ALL  , ""  ) ;
  main_shifr . localerus = ( strcmp  ( locale  , "ru_RU.UTF-8" ) ==  0 ) ;
  int exc = setjmp  ( main_shifr  . jump  ) ;
  if ( exc ) {
    fprintf ( stderr  , ( main_shifr . localerus ? u8"Исключение : %s\n" :
      "Exception : %s\n" ) , & ( ( *  main_shifr  . string_exception ) [ 0 ] ) ) ;
    shifr_destr ( & main_shifr ) ;
    return  exc ; }
    
  if  ( argc  <=  1 ) {
    int const e = show_help ( & main_shifr  ) ;
    shifr_destr ( & main_shifr ) ;
    return  e ; }
  
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
  
  { int argj = 1 ;
  for ( ; argv [ argj ] ; ++ argj ) {
    if ( flagreadpasswdfromfile ) {
      FILE * const f = fopen  ( argv  [ argj  ] , & ( "r" [ 0 ] ) ) ;
      if  ( not f ) {
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
      size_t  nr  ;
      size_t  ns  ;
      if ( main_shifr . use_version == 2 ) {
        ns  = password_letters2size ;
        nr = fread  ( ( char * ) & main_shifr  . password_letters2 , 1 , ns , f ) ; }
      else {
        ns  = password_letters3size ;
        nr = fread  ( ( char * ) & main_shifr  . password_letters3 , 1 , ns , f ) ; }
      if ( nr >= ns ) {
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
      test_password ( & main_shifr  , nr  ) ;
      string_to_password  ( & main_shifr  ) ;
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
        strncpy ( ( char * ) main_shifr  . password_letters2 , argv  [ argj  ] ,
          password_letters2size  ) ;
        string_to_password  ( & main_shifr ) ;
# ifdef SHIFR_DEBUG
      fputs ( ( main_shifr . localerus ?
        u8"из строки во внутренний пароль = " :
        "from string to internal password = " ) , stderr ) ;
      number_princ  ( v2 ) ( & main_shifr . raspr2  . pass . pub , stderr  ) ;
      fputs ( "\n" , stderr ) ;
# endif      
        }
      else {
        strncpy ( ( char * ) main_shifr  . password_letters3 , argv  [ argj  ] ,
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
        if  ( strcmp ( ( char * ) main_shifr  . password_letters3 , argv  [ argj  ] ) )  
          fprintf  ( stderr , main_shifr . localerus ?
            u8"Предупреждение! Пароль \'%s\' очень большой. Аналогичен \'%s\'\n" :
            "Warning! Password \'%s\' is very large. Same as \'%s\'\n"
            , argv  [ argj  ] , & ( main_shifr  . password_letters3  [ 0 ] ) ) ; }
      else {
        if  ( strcmp ( ( char * ) main_shifr  . password_letters2 , argv  [ argj  ] ) )  
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
        if (( strcmp ( argv[argj] , u8"--а26" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--a26" ) ==  0 )) { 
          main_shifr . password_alphabet = 26 ; }
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
    int const e = main_genpsw ( & main_shifr  ) ;
    shifr_destr ( & main_shifr ) ;
    return  e ; }
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
      shifr_deshi_size3 , stderr  ) ;
    printarr  ( ( strcp ) & "deshi" , ( arrcp ) & main_shifr . deshi3 , shifr_deshi_size3 ,
      stderr  ) ; }
  else  {
    printarr  ( ( strcp ) & "shifr" , ( arrcp ) & main_shifr . shifr2 , shifr_deshi_size2 ,
      stderr  ) ;
    printarr  ( ( strcp ) & "deshi" , ( arrcp ) & main_shifr . deshi2 , shifr_deshi_size2 ,
      stderr  ) ; }
# endif // SHIFR_DEBUG
  enum  { inputbuffersize = 0x1000  } ;
  enum  { outputbuffersize  = 0x3100  } ; // 0x30cd
  static  uint8_t inputbuffer [ inputbuffersize ] ;
  static  uint8_t outputbuffer  [ outputbuffersize ] ;
  if ( flagenc ) {
    if ( main_shifr . use_version == 3 ) 
      shifr_encode_file_v3  ( & main_shifr  , & inputbuffer , inputbuffersize ,
        & outputbuffer  , outputbuffersize  ) ;
    else
      if ( main_shifr . use_version == 2 ) 
        shifr_encode_file_v2  ( & main_shifr  , & inputbuffer , inputbuffersize ,
          & outputbuffer  , outputbuffersize  ) ; } // if flagenc
  else { // flagdec
    if ( main_shifr . use_version == 2 )
      shifr_decode_file_v2  ( & main_shifr  , & inputbuffer , inputbuffersize ,
        & outputbuffer  , outputbuffersize  ) ;
    else 
      shifr_decode_file_v3  ( & main_shifr  , & inputbuffer , inputbuffersize ,
        & outputbuffer  , outputbuffersize  ) ; }
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
  shifr_destr ( & main_shifr ) ;
  return  resulterror ; }
