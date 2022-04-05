# ifndef  SHIFRTYPEH
# define  SHIFRTYPEH

# include <stdint.h>

# define  strp  shifr_strp
typedef char ( * strp ) [ ] ;

# define  strvp shifr_strvp
typedef char  volatile  ( * strvp ) [ ] ;

# define  strcp  shifr_strcp
typedef char const ( * strcp ) [ ] ;

# define  strvcp  shifr_strvcp
typedef char  volatile  const ( * strvcp  ) [ ] ;

# define  arrp  shifr_arrp
typedef uint8_t ( * arrp ) [ ] ;

# define  arrcp  shifr_arrcp
typedef uint8_t const ( * arrcp ) [ ] ;

# define  s_arrcps  shifr_s_arrcps
struct  s_arrcps  ;

# define  arrcps  shifr_arrcps
typedef struct  s_arrcps  arrcps  ;

# define  s_arrps  shifr_s_arrps
struct  s_arrps  ;

# define  arrps  shifr_arrps
typedef struct  s_arrps arrps ;

# define  s_size_io shifr_s_size_io
struct  s_size_io ;

# define  size_io shifr_size_io
typedef struct  s_size_io size_io ;

# define  shifr_number_structtype( N ) \
  struct  shifr_s_number ## N ;
  
# define  shifr_number_type( N ) shifr_t_number ## N
# define  number_type shifr_number_type

# define  shifr_number_typedef( N ) \
  typedef struct  shifr_s_number ## N number_type ( N ) ;    
  
# define  shifr_number_priv_structtype( N ) \
  struct  shifr_s_number_priv ## N ;

# define  shifr_number_priv_type( N ) shifr_t_number_priv ## N
# define  number_priv_type shifr_number_priv_type

# define  shifr_number_priv_typedef( N ) \
  typedef struct  shifr_s_number_priv ## N number_priv_type ( N ) ;  

// log(2,16!) ceil 8 = 6
// log(2,64!) ceil 8 = 37
# define  e_number_size shifr_e_number_size
enum  e_number_size  { number_size2 = 6 , number_size3 = 37 }  ;

shifr_number_structtype( number_size2 )
shifr_number_typedef( number_size2 )
shifr_number_structtype( number_size3 )
shifr_number_typedef( number_size3 )

shifr_number_priv_structtype( number_size2 )
shifr_number_priv_typedef( number_size2 )
shifr_number_priv_structtype( number_size3 )
shifr_number_priv_typedef( number_size3 )

# define  s_raspr2  shifr_s_raspr2
struct  s_raspr2  ;
# define  t_raspr2  shifr_t_raspr2
typedef struct  s_raspr2  t_raspr2  ;

# define  s_raspr3  shifr_s_raspr3
struct  s_raspr3  ;
# define  t_raspr3  shifr_t_raspr3
typedef struct  s_raspr3  t_raspr3 ;

struct  s_ns_shifr  ;
typedef struct  s_ns_shifr  t_ns_shifr ;

# define  s_streambuf shifr_s_streambuf
struct  s_streambuf ;
# define  t_streambuf shifr_t_streambuf
typedef struct  s_streambuf t_streambuf ;

// 4 * 4 = 16
# define  deshi_size2 shifr_deshi_size2

// 8 * 8 = 64
# define  deshi_size3 shifr_deshi_size3
# define  e_deshi_size  shifr_e_deshi_size
enum  e_deshi_size  { deshi_size2 = 0x10 , deshi_size3 = 0x40 }  ;

# endif //  SHIFRTYPEH
