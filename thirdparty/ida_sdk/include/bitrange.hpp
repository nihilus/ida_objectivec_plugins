#ifndef _BITMASK_HPP
#define _BITMASK_HPP

//---------------------------------------------------------------------------
// class bitrange_t keeps offset/size of the value which occupies
// a number of contiguous bits within some container - generally a byte array.
// A special state - empty range (both offset and size are zeroes) - determines
// the value as all bits of the container
class bitrange_t
{
public:
  explicit bitrange_t(uint16 bit_ofs = 0, uint16 size_in_bits = 0);
  inline void init(uint16 bit_ofs, uint16 size_in_bits);
  inline void reset();          // make the bitrange empty
  inline bool empty() const;    // return TRUE if the bitrange is empty

  inline uint bitoff() const;   // offset of 1st bit
  inline uint bitsize() const;  // size of the value in bits
  inline uint bytesize() const; // size of the value in bytes
  inline uint64 mask64() const; // convert to mask of 64 bits

  // make the superposition of the current bitrange and given bitrange
  inline bool combine(const bitrange_t &subrange);

  // intersect two ranges
  inline void intersect(const bitrange_t &r);

  // create union of 2 ranges including the hole between them
  inline void create_union(const bitrange_t &r);

  // shift range down (left)
  inline void shift_down(uint cnt);
  // shift range up (right)
  inline void shift_up(uint cnt);

  // initialize bitrange_t with offset/size defined by given mask
  template <class T> inline void assign_max_nonzero(T mask);

  // extract a value from 'src' according to the bitrange
  // In: dst           - vector the extracted value will be stored to
  //     src, src_size - source buffer ptr/size
  //     is_mf         - is Msb First? (TRUE-big endian, FALSE-little endian)
  inline bool extract(bytevec_t *dst, const void *src, int src_size, bool is_mf) const;
  inline bool extract(void *dst, int dst_size, const void *src, int src_size, bool is_mf) const;

  // inject a value into 'dst' according to the bitrange
  // In: dst, dst_size - a buffer the value will be injected into
  //     src           - source value
  //     is_mf         - is Msb First? (TRUE-big endian, FALSE-little endian)
  inline bool inject(void *dst, int dst_size, const void *src, int src_size, bool is_mf) const;
  inline bool inject(void *dst, int dst_size, const bytevec_t &src, bool is_mf) const;

  DECLARE_COMPARISONS(bitrange_t);

private:
  uint16 offset;    // offset of 1st bit starting with the lowest bit
  uint16 nbits;     // size of the value in bits
};

//---------------------------------------------------------------------------
inline bitrange_t::bitrange_t(uint16 bit_ofs, uint16 size_in_bits)
  : offset(bit_ofs), nbits(size_in_bits)
{
}

//---------------------------------------------------------------------------
inline void bitrange_t::init(uint16 bit_ofs, uint16 size_in_bits)
{
  offset = bit_ofs;
  nbits  = size_in_bits;
}

//---------------------------------------------------------------------------
inline void bitrange_t::reset()
{
  init(0, 0);
}

//---------------------------------------------------------------------------
inline bool bitrange_t::empty() const
{
  return nbits == 0;
}

//---------------------------------------------------------------------------
inline uint bitrange_t::bitoff() const
{
  return offset;
}

//---------------------------------------------------------------------------
inline uint bitrange_t::bitsize() const
{
  return nbits;
}

//---------------------------------------------------------------------------
inline uint bitrange_t::bytesize() const
{
  return (nbits + 8-1) / 8;
}

//--------------------------------------------------------------------------
inline uint64 bitrange_t::mask64() const
{
  return empty() ? 0 : (left_shift(uint64(1), nbits)-1) << offset;
}

//--------------------------------------------------------------------------
inline bool bitrange_t::combine(const bitrange_t &submask)
{
  if ( !empty() && submask.bitoff() + submask.bitsize() > bitsize() )
    return false;
  init(bitoff() + submask.bitoff(), submask.bitsize());
  return true;
}

//--------------------------------------------------------------------------
inline void bitrange_t::intersect(const bitrange_t &r)
{
  uint16 e1 = offset + nbits;
  uint16 e2 = r.offset + r.nbits;
  uint16 e = qmin(e1, e2);
  uint16 s = qmax(offset, r.offset);
  if ( s > e )
  {
    s = 0;
    e = 0;
  }
  init(s, e-s);
}

//--------------------------------------------------------------------------
inline void bitrange_t::create_union(const bitrange_t &r)
{
  uint16 e1 = offset + nbits;
  uint16 e2 = r.offset + r.nbits;
  uint16 e = qmax(e1, e2);
  uint16 s = qmin(offset, r.offset);
  init(s, e-s);
}

//--------------------------------------------------------------------------
inline int bitrange_t::compare(const bitrange_t &r) const
{
  if ( offset != r.offset )
    return offset < r.offset ? -1 : 1;
  if ( nbits != r.nbits )
    return nbits < r.nbits ? -1 : 1;
  return 0;
}

//--------------------------------------------------------------------------
inline void bitrange_t::shift_down(uint cnt)
{
  if ( cnt > offset )
  {
    cnt -= offset;
    offset = 0;
    if ( cnt > nbits )
      nbits = 0;
    else
      nbits -= cnt;
  }
  else
  {
    offset -= cnt;
  }
}

//--------------------------------------------------------------------------
inline void bitrange_t::shift_up(uint cnt)
{
  offset += cnt;
}

//--------------------------------------------------------------------------
template <class T> inline void bitrange_t::assign_max_nonzero(T mask)
{
  if ( mask == T(0) )
  {
    reset();
    return;
  }
  int i = 0;
  T bit = T(1);
  for ( i=0; i < sizeof(T)*8; ++i, bit <<= 1 )
    if ( (mask & bit) != 0 )
      break;
  offset = i;
  i = sizeof(T)*8 - 1;
  bit = left_shift(T(1), i);
  while ( i >= offset )
  {
    if ( (mask & bit) != 0 )
      break;
    --i;
    bit >>= 1;
  }
  nbits = i - offset + 1;
}

//--------------------------------------------------------------------------
// Helper functions. Should not be called directly!
#ifndef SWIG
idaman bool ida_export bitrange_t_extract_using_bitrange(const bitrange_t *bm, void *dst, int dst_size, const void *src, int src_size, bool is_mf);
idaman bool ida_export bitrange_t_inject_using_bitrange(const bitrange_t *bm, void *dst, int dst_size, const void *src, int src_size, bool is_mf);
#else
#endif // SWIG

//--------------------------------------------------------------------------
inline bool bitrange_t::extract(void *dst, int dst_size, const void *src, int src_size, bool is_mf) const
{
  return bitrange_t_extract_using_bitrange(this, dst, dst_size, src, src_size, is_mf);
}

//--------------------------------------------------------------------------
inline bool bitrange_t::extract(bytevec_t *dst, const void *src, int src_size, bool is_mf) const
{
  int dst_size = empty() ? src_size : bytesize();
  dst->resize(dst_size);
  return bitrange_t_extract_using_bitrange(this, dst->begin(), dst_size, src, src_size, is_mf);
}

//--------------------------------------------------------------------------
inline bool bitrange_t::inject(void *dst, int dst_size, const void *src, int src_size, bool is_mf) const
{
  return bitrange_t_inject_using_bitrange(this, dst, dst_size, src, src_size, is_mf);
}

//--------------------------------------------------------------------------
inline bool bitrange_t::inject(void *dst, int dst_size, const bytevec_t &src, bool is_mf) const
{
  return bitrange_t_inject_using_bitrange(this, dst, dst_size, src.begin(), src.size(), is_mf);
}

#endif // define _BITMASK_HPP
