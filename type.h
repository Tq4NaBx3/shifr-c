# ifndef  SHIFRTYPEH
# define  SHIFRTYPEH

# include <stdint.h>

# define  strp  shifr_strp
typedef char ( * strp ) [ ] ;    

# define  strcp  shifr_strcp
typedef char const ( * strcp ) [ ] ;

# define  arrp  shifr_arrp
typedef uint8_t ( * arrp ) [ ] ;

# define  arrcp  shifr_arrcp
typedef uint8_t const ( * arrcp ) [ ] ;

# define  shifr_number_structtype( N ) \
  struct  shifr_s_number ## N ;

# define  shifr_number_type( N ) shifr_t_number ## N
# define  number_type shifr_number_type

# define  shifr_number_typedef( N ) \
  typedef struct  shifr_s_number ## N number_type ( N ) ;  

// log(2,16!) ceil 8 = 6
// log(2,64!) ceil 8 = 37
# define  e_number_size shifr_e_number_size
enum  e_number_size  { number_size2 = 6 , number_size3 = 37 }  ;

shifr_number_structtype( number_size2 )
shifr_number_typedef( number_size2 )
shifr_number_structtype( number_size3 )
shifr_number_typedef( number_size3 )

# define  s_raspr4  shifr_s_raspr4
struct  s_raspr4  ;
# define  t_raspr4  shifr_t_raspr4
typedef struct  s_raspr4  t_raspr4  ;

# define  s_raspr6  shifr_s_raspr6
struct  s_raspr6  ;
# define  t_raspr6  shifr_t_raspr6
typedef struct  s_raspr6  t_raspr6 ;

struct  s_ns_shifr  ;
typedef struct  s_ns_shifr  t_ns_shifr ;

# define  s_streambuf shifr_s_streambuf
struct  s_streambuf ;
# define  t_streambuf shifr_t_streambuf
typedef struct  s_streambuf t_streambuf ;

// 4 * 4 = 16
# define  deshi_size2 shifr_deshi_size2

// 8 * 8 = 64
# define  deshi_size6 shifr_deshi_size6
# define  e_deshi_size  shifr_e_deshi_size
enum  e_deshi_size  { deshi_size2 = 0x10 , deshi_size6 = 0x40 }  ;

# endif //  SHIFRTYPEH
