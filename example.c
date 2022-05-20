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
  
// ! buf , bufbitsize to init fun
  shif . filebufto . buf = 0 ;
  
  shifr_password_load_uni ( & shif ) ;
  enum { inbufsize = 0x100 } ;
  uint8_t inbuf [ inbufsize ] = "Lambda" ;
  
  enum { outbufsize = 0x400 } ;
  uint8_t outbuf [ outbufsize ] ;
  shifr_size_io sizeio  = shifr_encrypt3  ( & shif ,
    ( shifr_arrcps ) { .cp = ( shifr_arrcp ) & inbuf ,
      .s = strlen ( (char const*)inbuf ) } ,
    ( shifr_arrps ) { .p = & outbuf , .s = outbufsize - 1 } ) ;
  fprintf ( stdout , "inbuf = `%s`\n" , inbuf ) ;
  fprintf ( stdout  , "sizeio . i = %zu .o = %zu\n" , sizeio . i ,
    sizeio . o ) ;
  outbuf [ sizeio . o ] = '\00' ;
  fprintf ( stdout , "outbuf = `%s`\n" , outbuf ) ;
  strcpy ( (char *)inbuf , " !" ) ;
  
  enum { outbuf2size = 0x400 } ;
  uint8_t outbuf2 [ outbuf2size ] ;
  shifr_size_io sizeio2  = shifr_encrypt3  ( & shif ,
    ( shifr_arrcps ) { .cp = ( shifr_arrcp ) & inbuf ,
      .s = strlen ( (char const*)inbuf ) } ,
    ( shifr_arrps ) { .p = & outbuf2 , .s = outbuf2size - 1 } ) ;
  fprintf ( stdout , "second inbuf = `%s`\n" , inbuf ) ;
  fprintf ( stdout  , "second sizeio . i = %zu .o = %zu\n" , sizeio2 . i , sizeio2 . o ) ;
  outbuf2 [ sizeio2 . o ] = '\00' ;
  fprintf ( stdout , "second outbuf = `%s`\n" , outbuf2 ) ;
  
  enum { outbuffsize = 0x40 } ;
  uint8_t outbuff [ outbuffsize ] ;
  uint8_t const bytes = shifr_streambuf_writeflushzero3 ( & shif ,
          ( shifr_arrps ) { .p = & outbuff , .s = outbuffsize - 1 } ) ;
  fprintf ( stdout  , "flush bytes = %u\n" , bytes ) ;
  outbuff [ bytes ] = '\00' ;
  fprintf ( stdout , "flush outbuf = `%s`\n" , outbuff ) ;
  fprintf ( stdout , "full string = `%s" , outbuf ) ;
  fputs ( (char *)outbuf2 , stdout ) ;
  fprintf ( stdout , "%s`\n" , outbuff ) ;
  
// ! to make func sole_init
  
  shif .  old_last_data = 0 ;
  shif .  old_last_sole = 0 ;  
  
  enum { decbufsize = 0x100 } ;
  uint8_t decbuf [ decbufsize ] ;
  shifr_size_io sizeiodec  = shifr_decrypt3  ( & shif ,
    ( shifr_arrcps  ) { . cp  = ( shifr_arrcp ) & outbuf , . s = sizeio . o } ,
    ( shifr_arrps ) { . p = & decbuf , . s = decbufsize - 1 } ) ;
  fprintf ( stdout , "outbuf = `%s`\n" , outbuf ) ;
  fprintf ( stdout  , "sizeio . i = %zu .o = %zu\n" , sizeiodec . i ,
    sizeiodec . o ) ;
  decbuf [ sizeiodec . o ] = '\00' ;
  fprintf ( stdout , "decbuf = `%s`\n" , decbuf ) ;
  
  enum { decbuf2size = 0x100 } ;
  uint8_t decbuf2 [ decbuf2size ] ;
  shifr_size_io sizeiodec2  = shifr_decrypt3  ( & shif ,
    ( shifr_arrcps  ) { . cp  = ( shifr_arrcp ) & outbuf2 ,
      . s = sizeio2 . o } ,
    ( shifr_arrps ) { . p = & decbuf2 , . s = decbuf2size - 1 } ) ;
  fprintf ( stdout , "outbuf = `%s`\n" , outbuf2 ) ;
  fprintf ( stdout  , "sizeio . i = %zu .o = %zu\n" , sizeiodec2 . i ,
    sizeiodec2 . o ) ;
  decbuf2 [ sizeiodec2 . o ] = '\00' ;
  fprintf ( stdout , "decbuf = `%s`\n" , decbuf2 ) ;
  
  
  
  shifr_destr ( & shif ) ; }
