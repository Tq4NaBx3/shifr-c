// make example && ./example
# include <string.h>
# include "define.h"
# include "inline.h"

int main  ( int argc , char * argv [ ] ) {
  t_ns_shifr  shif ;
  shifr_init  ( & shif ) ;
  shif . flagtext = true  ;
  strncpy ( ( char * ) shif . password_letters3 , "qwerty" ,
          shifr_password_letters3size ) ; 
  shifr_string_to_password  ( & shif ) ;
  shifr_streambuf_init  ( & shif . filebuffrom , shif . filefrom )  ;
  shifr_streambuf_init  ( & shif . filebufto , shif . fileto )  ;
  shifr_password_load_uni ( & shif ) ;
  enum { inbufsize = 0x100 } ;
  uint8_t inbuf [ inbufsize ] = "Lambda" ;
  enum { outbufsize = 0x400 } ;
  uint8_t outbuf [ outbufsize ] ;
  shifr_size_io sizeio  = shifr_encrypt3  ( & shif ,
            ( shifr_arrcps ) { .cp = ( shifr_arrcp ) & inbuf , .s = strlen ( (char const*)inbuf ) } ,
            ( shifr_arrps ) { .p = & outbuf , .s = outbufsize - 1 } ) ;
  fprintf ( stdout , "inbuf = `%s`\n" , inbuf ) ;
  fprintf ( stdout  , "sizeio . i = %zu .o = %zu\n" , sizeio . i , sizeio . o ) ;
  outbuf [ sizeio . o ] = '\00' ;
  fprintf ( stdout , "outbuf = `%s`\n" , outbuf ) ;
  strcpy ( (char *)inbuf , " !" ) ;
  sizeio  = shifr_encrypt3  ( & shif ,
            ( shifr_arrcps ) { .cp = ( shifr_arrcp ) & inbuf , .s = strlen ( (char const*)inbuf ) } ,
            ( shifr_arrps ) { .p = & outbuf , .s = outbufsize - 1 } ) ;
  fprintf ( stdout , "inbuf = `%s`\n" , inbuf ) ;
  fprintf ( stdout  , "sizeio . i = %zu .o = %zu\n" , sizeio . i , sizeio . o ) ;
  outbuf [ sizeio . o ] = '\00' ;
  fprintf ( stdout , "outbuf = `%s`\n" , outbuf ) ;
  shifr_destr ( & shif ) ; }
