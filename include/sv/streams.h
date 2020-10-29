// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef SV_STREAMS_H
#define SV_STREAMS_H

#include <sv/serialize.h>
#include <sv/support/allocators/zeroafterfree.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ios>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace sv {

template <typename Stream> class OverrideStream {
    Stream *stream;

    const int nType;
    const int nVersion;

public:
    OverrideStream(Stream *stream_, int nType_, int nVersion_)
        : stream(stream_), nType(nType_), nVersion(nVersion_) {}

    template <typename T> OverrideStream<Stream> &operator<<(const T &obj) {
        // Serialize to this stream
        sv::Serialize(*this, obj);
        return (*this);
    }

    template <typename T> OverrideStream<Stream> &operator>>(T &obj) {
        // Unserialize from this stream
        sv::Unserialize(*this, obj);
        return (*this);
    }

    void write(const char *pch, size_t nSize) { stream->write(pch, nSize); }

    void read(char *pch, size_t nSize) { stream->read(pch, nSize); }

    int GetVersion() const { return nVersion; }
    int GetType() const { return nType; }
};

template <typename S> OverrideStream<S> WithOrVersion(S *s, int nVersionFlag) {
    return OverrideStream<S>(s, s->GetType(), s->GetVersion() | nVersionFlag);
}

/**
 * Minimal stream for overwriting and/or appending to an existing byte vector.
 *
 * The referenced vector will grow as necessary.
 */
class CVectorWriter {
public:
    /**
     * @param[in]  nTypeIn Serialization Type
     * @param[in]  nVersionIn Serialization Version (including any flags)
     * @param[in]  vchDataIn  Referenced byte vector to overwrite/append
     * @param[in]  nPosIn Starting position. Vector index where writes should
     * start. The vector will initially grow as necessary to  max(index,
     * vec.size()). So to append, use vec.size().
     */
    CVectorWriter(int nTypeIn, int nVersionIn, std::vector<uint8_t> &vchDataIn,
                  size_t nPosIn)
        : nType(nTypeIn), nVersion(nVersionIn), vchData(vchDataIn),
          nPos(nPosIn) {
        if (nPos > vchData.size()) vchData.resize(nPos);
    }
    /**
     * (other params same as above)
     * @param[in]  args  A list of items to serialize starting at nPos.
     */
    template <typename... Args>
    CVectorWriter(int nTypeIn, int nVersionIn, std::vector<uint8_t> &vchDataIn,
                  size_t nPosIn, Args &&... args)
        : CVectorWriter(nTypeIn, nVersionIn, vchDataIn, nPosIn) {
        sv::SerializeMany(*this, std::forward<Args>(args)...);
    }
    void write(const char *pch, size_t nSize) {
        assert(nPos <= vchData.size());
        size_t nOverwrite = std::min(nSize, vchData.size() - nPos);
        if (nOverwrite) {
            memcpy(vchData.data() + nPos,
                   reinterpret_cast<const uint8_t *>(pch), nOverwrite);
        }
        if (nOverwrite < nSize) {
            vchData.insert(vchData.end(),
                           reinterpret_cast<const uint8_t *>(pch) + nOverwrite,
                           reinterpret_cast<const uint8_t *>(pch) + nSize);
        }
        nPos += nSize;
    }
    template <typename T> CVectorWriter &operator<<(const T &obj) {
        // Serialize to this stream
        sv::Serialize(*this, obj);
        return (*this);
    }
    int GetVersion() const { return nVersion; }
    int GetType() const { return nType; }
    void seek(size_t nSize) {
        nPos += nSize;
        if (nPos > vchData.size()) vchData.resize(nPos);
    }

private:
    const int nType;
    const int nVersion;
    std::vector<uint8_t> &vchData;
    size_t nPos;
};

/**
 * Double ended buffer combining vector and stream-like interfaces.
 *
 * >> and << read and write unformatted data using the above serialization
 * templates. Fills with data in linear time; some stringstream implementations
 * take N^2 time.
 */
class CDataStream {
protected:
    typedef CSerializeData vector_type;
    vector_type vch;
    unsigned int nReadPos;

    int nType;
    int nVersion;

public:
    typedef vector_type::allocator_type allocator_type;
    typedef vector_type::size_type size_type;
    typedef vector_type::difference_type difference_type;
    typedef vector_type::reference reference;
    typedef vector_type::const_reference const_reference;
    typedef vector_type::value_type value_type;
    typedef vector_type::iterator iterator;
    typedef vector_type::const_iterator const_iterator;
    typedef vector_type::reverse_iterator reverse_iterator;

    explicit CDataStream(int nTypeIn, int nVersionIn) {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const_iterator pbegin, const_iterator pend, int nTypeIn,
                int nVersionIn)
        : vch(pbegin, pend) {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const char *pbegin, const char *pend, int nTypeIn,
                int nVersionIn)
        : vch(pbegin, pend) {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const vector_type &vchIn, int nTypeIn, int nVersionIn)
        : vch(vchIn.begin(), vchIn.end()) {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const std::vector<char> &vchIn, int nTypeIn, int nVersionIn)
        : vch(vchIn.begin(), vchIn.end()) {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const std::vector<uint8_t> &vchIn, int nTypeIn, int nVersionIn)
        : vch(vchIn.begin(), vchIn.end()) {
        Init(nTypeIn, nVersionIn);
    }

    template <typename... Args>
    CDataStream(int nTypeIn, int nVersionIn, Args &&... args) {
        Init(nTypeIn, nVersionIn);
        sv::SerializeMany(*this, std::forward<Args>(args)...);
    }

    void Init(int nTypeIn, int nVersionIn) {
        nReadPos = 0;
        nType = nTypeIn;
        nVersion = nVersionIn;
    }

    CDataStream &operator+=(const CDataStream &b) {
        vch.insert(vch.end(), b.begin(), b.end());
        return *this;
    }

    friend CDataStream operator+(const CDataStream &a, const CDataStream &b) {
        CDataStream ret = a;
        ret += b;
        return (ret);
    }

    std::string str() const { return (std::string(begin(), end())); }

    //
    // Vector subset
    //
    const_iterator begin() const { return vch.begin() + nReadPos; }
    iterator begin() { return vch.begin() + nReadPos; }
    const_iterator end() const { return vch.end(); }
    iterator end() { return vch.end(); }
    size_type size() const { return vch.size() - nReadPos; }
    bool empty() const { return vch.size() == nReadPos; }
    void resize(size_type n, value_type c = 0) { vch.resize(n + nReadPos, c); }
    void reserve(size_type n) { vch.reserve(n + nReadPos); }
    const_reference operator[](size_type pos) const {
        return vch[pos + nReadPos];
    }
    reference operator[](size_type pos) { return vch[pos + nReadPos]; }
    void clear() {
        vch.clear();
        nReadPos = 0;
    }
    iterator insert(iterator it, const char &x = char()) {
        return vch.insert(it, x);
    }
    void insert(iterator it, size_type n, const char &x) {
        vch.insert(it, n, x);
    }
    value_type *data() { return vch.data() + nReadPos; }
    const value_type *data() const { return vch.data() + nReadPos; }

    void insert(iterator it, std::vector<char>::const_iterator first,
                std::vector<char>::const_iterator last) {
        if (last == first) {
            return;
        }

        assert(last - first > 0);
        if (it == vch.begin() + nReadPos &&
            (unsigned int)(last - first) <= nReadPos) {
            // special case for inserting at the front when there's room
            nReadPos -= (last - first);
            memcpy(&vch[nReadPos], &first[0], last - first);
        } else {
            vch.insert(it, first, last);
        }
    }

    void insert(iterator it, const char *first, const char *last) {
        if (last == first) {
            return;
        }

        assert(last - first > 0);
        if (it == vch.begin() + nReadPos &&
            (unsigned int)(last - first) <= nReadPos) {
            // special case for inserting at the front when there's room
            nReadPos -= (last - first);
            memcpy(&vch[nReadPos], &first[0], last - first);
        } else {
            vch.insert(it, first, last);
        }
    }

    iterator erase(iterator it) {
        if (it == vch.begin() + nReadPos) {
            // special case for erasing from the front
            if (++nReadPos >= vch.size()) {
                // whenever we reach the end, we take the opportunity to clear
                // the buffer
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            }
            return vch.begin() + nReadPos;
        } else {
            return vch.erase(it);
        }
    }

    iterator erase(iterator first, iterator last) {
        if (first == vch.begin() + nReadPos) {
            // special case for erasing from the front
            if (last == vch.end()) {
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            } else {
                nReadPos = (last - vch.begin());
                return last;
            }
        } else
            return vch.erase(first, last);
    }

    inline void Compact() {
        vch.erase(vch.begin(), vch.begin() + nReadPos);
        nReadPos = 0;
    }

    bool Rewind(size_type n) {
        // Rewind by n characters if the buffer hasn't been compacted yet
        if (n > nReadPos) return false;
        nReadPos -= n;
        return true;
    }

    //
    // Stream subset
    //
    bool eof() const { return size() == 0; }
    CDataStream *rdbuf() { return this; }
    int in_avail() { return size(); }

    void SetType(int n) { nType = n; }
    int GetType() const { return nType; }
    void SetVersion(int n) { nVersion = n; }
    int GetVersion() const { return nVersion; }

    void read(char *pch, size_t nSize) {
        if (nSize == 0) {
            return;
        }

        // Read from the beginning of the buffer
        unsigned int nReadPosNext = nReadPos + nSize;
        if (nReadPosNext >= vch.size()) {
            if (nReadPosNext > vch.size()) {
                throw std::ios_base::failure(
                    "CDataStream::read(): end of data");
            }
            memcpy(pch, &vch[nReadPos], nSize);
            nReadPos = 0;
            vch.clear();
            return;
        }
        memcpy(pch, &vch[nReadPos], nSize);
        nReadPos = nReadPosNext;
    }

    void ignore(int nSize) {
        // Ignore from the beginning of the buffer
        if (nSize < 0) {
            throw std::ios_base::failure(
                "CDataStream::ignore(): nSize negative");
        }
        unsigned int nReadPosNext = nReadPos + nSize;
        if (nReadPosNext >= vch.size()) {
            if (nReadPosNext > vch.size())
                throw std::ios_base::failure(
                    "CDataStream::ignore(): end of data");
            nReadPos = 0;
            vch.clear();
            return;
        }
        nReadPos = nReadPosNext;
    }

    void write(const char *pch, size_t nSize) {
        // Write to the end of the buffer
        vch.insert(vch.end(), pch, pch + nSize);
    }

    template <typename Stream> void Serialize(Stream &s) const {
        // Special case: stream << stream concatenates like stream += stream
        if (!vch.empty()) s.write((char *)&vch[0], vch.size() * sizeof(vch[0]));
    }

    template <typename T> CDataStream &operator<<(const T &obj) {
        // Serialize to this stream
        sv::Serialize(*this, obj);
        return (*this);
    }

    template <typename T> CDataStream &operator>>(T &obj) {
        // Unserialize from this stream
        sv::Unserialize(*this, obj);
        return (*this);
    }

    void GetAndClear(CSerializeData &d) {
        d.insert(d.end(), begin(), end());
        clear();
    }

    /**
     * XOR the contents of this stream with a certain key.
     *
     * @param[in] key    The key used to XOR the data in this stream.
     */
    void Xor(const std::vector<uint8_t> &key) {
        if (key.size() == 0) {
            return;
        }

        for (size_type i = 0, j = 0; i != size(); i++) {
            vch[i] ^= key[j++];

            // This potentially acts on very many bytes of data, so it's
            // important that we calculate `j`, i.e. the `key` index in this way
            // instead of doing a %, which would effectively be a division for
            // each byte Xor'd -- much slower than need be.
            if (j == key.size()) j = 0;
        }
    }
};

/**
 * Non-refcounted RAII wrapper for FILE*
 *
 * Will automatically close the file when it goes out of scope if not null. If
 * you're returning the file pointer, return file.release(). If you need to
 * close the file early, use file.fclose() instead of fclose(file).
 */
class CAutoFile {
private:
    // Disallow copies
    CAutoFile(const CAutoFile &);
    CAutoFile &operator=(const CAutoFile &);

    const int nType;
    const int nVersion;

    FILE *file;

public:
    CAutoFile(FILE *filenew, int nTypeIn, int nVersionIn)
        : nType(nTypeIn), nVersion(nVersionIn) {
        file = filenew;
    }

    ~CAutoFile() { fclose(); }

    void fclose() {
        if (file) {
            ::fclose(file);
            file = nullptr;
        }
    }

    /**
     * Get wrapped FILE* with transfer of ownership.
     * @note This will invalidate the CAutoFile object, and makes it the
     * responsibility of the caller of this function to clean up the returned
     * FILE*.
     */
    FILE *release() {
        FILE *ret = file;
        file = nullptr;
        return ret;
    }

    /**
     * Get wrapped FILE* without transfer of ownership.
     * @note Ownership of the FILE* will remain with this class. Use this only
     * if the scope of the CAutoFile outlives use of the passed pointer.
     */
    FILE *Get() const { return file; }

    /** Return true if the wrapped FILE* is nullptr, false otherwise. */
    bool IsNull() const { return (file == nullptr); }

    //
    // Stream subset
    //
    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }

    void read(char *pch, size_t nSize) {
        if (!file)
            throw std::ios_base::failure(
                "CAutoFile::read: file handle is nullptr");
        if (fread(pch, 1, nSize, file) != nSize)
            throw std::ios_base::failure(feof(file)
                                             ? "CAutoFile::read: end of file"
                                             : "CAutoFile::read: fread failed");
    }

    void ignore(size_t nSize) {
        if (!file)
            throw std::ios_base::failure(
                "CAutoFile::ignore: file handle is nullptr");
        uint8_t data[4096];
        while (nSize > 0) {
            size_t nNow = std::min<size_t>(nSize, sizeof(data));
            if (fread(data, 1, nNow, file) != nNow)
                throw std::ios_base::failure(
                    feof(file) ? "CAutoFile::ignore: end of file"
                               : "CAutoFile::read: fread failed");
            nSize -= nNow;
        }
    }

    void write(const char *pch, size_t nSize) {
        if (!file)
            throw std::ios_base::failure(
                "CAutoFile::write: file handle is nullptr");
        if (fwrite(pch, 1, nSize, file) != nSize)
            throw std::ios_base::failure("CAutoFile::write: write failed");
    }

    template <typename T> CAutoFile &operator<<(const T &obj) {
        // Serialize to this stream
        if (!file)
            throw std::ios_base::failure(
                "CAutoFile::operator<<: file handle is nullptr");
        sv::Serialize(*this, obj);
        return (*this);
    }

    template <typename T> CAutoFile &operator>>(T &obj) {
        // Unserialize from this stream
        if (!file)
            throw std::ios_base::failure(
                "CAutoFile::operator>>: file handle is nullptr");
        sv::Unserialize(*this, obj);
        return (*this);
    }
};

/**
 * Non-refcounted RAII wrapper around a FILE* that implements a ring buffer to
 * deserialize from. It guarantees the ability to rewind a given number of
 * bytes.
 *
 * Will automatically close the file when it goes out of scope if not null. If
 * you need to close the file early, use file.fclose() instead of fclose(file).
 */
class CBufferedFile {
private:
    // Disallow copies
    CBufferedFile(const CBufferedFile &);
    CBufferedFile &operator=(const CBufferedFile &);

    const int nType;
    const int nVersion;

    // source file
    FILE *src;
    // how many bytes have been read from source
    uint64_t nSrcPos;
    // how many bytes have been read from this
    uint64_t nReadPos;
    // up to which position we're allowed to read
    uint64_t nReadLimit;
    // how many bytes we guarantee to rewind
    uint64_t nRewind;
    // the buffer
    std::vector<char> vchBuf;

protected:
    // read data from the source to fill the buffer
    bool Fill() {
        unsigned int pos = nSrcPos % vchBuf.size();
        unsigned int readNow = vchBuf.size() - pos;
        unsigned int nAvail = vchBuf.size() - (nSrcPos - nReadPos) - nRewind;
        if (nAvail < readNow) readNow = nAvail;
        if (readNow == 0) return false;
        size_t read = fread((void *)&vchBuf[pos], 1, readNow, src);
        if (read == 0) {
            throw std::ios_base::failure(
                feof(src) ? "CBufferedFile::Fill: end of file"
                          : "CBufferedFile::Fill: fread failed");
        } else {
            nSrcPos += read;
            return true;
        }
    }

public:
    CBufferedFile(FILE *fileIn, uint64_t nBufSize, uint64_t nRewindIn,
                  int nTypeIn, int nVersionIn)
        : nType(nTypeIn), nVersion(nVersionIn), nSrcPos(0), nReadPos(0),
          nReadLimit((uint64_t)(-1)), nRewind(nRewindIn), vchBuf(nBufSize, 0) {
        src = fileIn;
    }

    ~CBufferedFile() { fclose(); }

    int GetVersion() const { return nVersion; }
    int GetType() const { return nType; }

    void fclose() {
        if (src) {
            ::fclose(src);
            src = nullptr;
        }
    }

    // check whether we're at the end of the source file
    bool eof() const { return nReadPos == nSrcPos && feof(src); }

    // read a number of bytes
    void read(char *pch, size_t nSize) {
        if (nSize + nReadPos > nReadLimit)
            throw std::ios_base::failure("Read attempted past buffer limit");
        while (nSize > 0) {
            if (nReadPos == nSrcPos) Fill();
            unsigned int pos = nReadPos % vchBuf.size();
            size_t nNow = nSize;
            if (nNow + pos > vchBuf.size()) nNow = vchBuf.size() - pos;
            if (nNow + nReadPos > nSrcPos) nNow = nSrcPos - nReadPos;
            memcpy(pch, &vchBuf[pos], nNow);
            nReadPos += nNow;
            pch += nNow;
            nSize -= nNow;
        }
    }

    // return the current reading position
    uint64_t GetPos() { return nReadPos; }

    // rewind to a given reading position
    bool SetPos(uint64_t nPos) {
        nReadPos = nPos;
        if (nReadPos + nRewind < nSrcPos) {
            nReadPos = nSrcPos - nRewind;
            return false;
        } else if (nReadPos > nSrcPos) {
            nReadPos = nSrcPos;
            return false;
        } else {
            return true;
        }
    }

    // Prevent reading beyond a certain position. No argument removes the limit.
    bool SetLimit(uint64_t nPos = (uint64_t)(-1)) {
        if (nPos < nReadPos) return false;
        nReadLimit = nPos;
        return true;
    }

    template <typename T> CBufferedFile &operator>>(T &obj) {
        // Unserialize from this stream
        sv::Unserialize(*this, obj);
        return (*this);
    }

    // search for a given byte in the stream, and remain positioned on it
    void FindByte(char ch) {
        while (true) {
            if (nReadPos == nSrcPos) Fill();
            if (vchBuf[nReadPos % vchBuf.size()] == ch) break;
            nReadPos++;
        }
    }
};

/**
 * A pointer to read only contiguous data buffer of a certain size.
 * CSpan doesn't take ownership of the underlying buffer so it is up to the
 * user to guarantee that the buffer lives longer than the CSpan pointing to it.
 */
class CSpan
{
public:
    CSpan() {/**/}

    CSpan(const uint8_t* const begin, size_t size)
        : mBegin{begin}
        , mSize{size}
    {/**/}

    const uint8_t* Begin() const {return mBegin;}
    size_t Size() const {return mSize;}

private:
    const uint8_t* mBegin = nullptr;
    size_t mSize = 0;
};

/**
 * Base class for forward readlonly streams of data that returns the underlying
 * data in chunks of up to requested size.
 * If a read error occurs while using CForwardReadonlyStream instance an
 * exception is thrown and stream should not be used after that point as it will
 * be in an invalid state.
 */
class CForwardReadonlyStream
{
public:
    virtual ~CForwardReadonlyStream() = default;

    virtual bool EndOfStream() const = 0;
    /**
     * Read next span of data that is up to maxSize long.
     * Returned CSpan is valid until the next call to Read() or until stream
     * is destroyed.
     * Span can return less than maxSize bytes if end of stream is reached
     * which can be checked by call to EndOfStream function.
     * In case EndOfStream is false and Read span returned size of 0 the data
     * is still being prepared and will be returned on next call to Read.
     */
    virtual CSpan Read(size_t maxSize) = 0;
};

/**
 * Base class for forward readlonly streams of data that returns the underlying
 * data in chunks of up to requested size.
 * If a read error occurs while using CForwardAsyncReadonlyStream instance an
 * exception is thrown and stream should not be used after that point as it will
 * be in an invalid state.
 */
class CForwardAsyncReadonlyStream
{
public:
    virtual ~CForwardAsyncReadonlyStream() = default;

    virtual bool EndOfStream() const = 0;
    /**
     * Read next span of data that is up to maxSize long.
     * Returned CSpan is valid until the next call to Read() or until stream
     * is destroyed.
     * Span can return less than maxSize bytes if end of stream is reached
     * which can be checked by call to EndOfStream function.
     * In case EndOfStream is false and Read span returned size of 0 the data
     * is still being prepared and will be returned on next call to Read.
     */
    virtual CSpan ReadAsync(size_t maxSize) = 0;
};

// helper function for use with std::unique_ptr to enable RAII file closing
struct CCloseFile
{
    void operator()(FILE* file) { ::fclose(file); }
};

/**
 * RAII file reader for use with streams that want to take ownership of the
 * underlying FILE pointer. File pointer is closed once the CFileReader instance
 * gets out of scope.
 */
class CFileReader
{
public:
    CFileReader(std::unique_ptr<FILE, CCloseFile>&& file)
        : mFile{std::move(file)}
    {
        assert(mFile);
    }

    CFileReader(CFileReader&&) = default;
    CFileReader& operator=(CFileReader&&) = default;

    CFileReader(const CFileReader&) = delete;
    CFileReader& operator=(const CFileReader&) = delete;

    size_t Read(char* pch, size_t maxSize)
    {
        size_t read = fread(pch, 1, maxSize, mFile.get());

        if (read == 0 && !EndOfStream())
        {
            throw std::ios_base::failure{"CFileReader::Read: fread failed"};
        }

        return read;
    }

    bool EndOfStream() const
    {
        return feof(mFile.get());
    }

private:
    std::unique_ptr<FILE, CCloseFile> mFile;
};

/**
 * File reader for use with streams that don't want to take ownership of the
 * underlying FILE pointer - it's up to the file pointer provider to close it
 * afterwards.
 */
class CNonOwningFileReader
{
public:
    CNonOwningFileReader(FILE* file)
        : mFile{file}
    {
        assert(mFile);
    }

    CNonOwningFileReader(CNonOwningFileReader&&) = default;
    CNonOwningFileReader& operator=(CNonOwningFileReader&&) = default;

    CNonOwningFileReader(const CNonOwningFileReader&) = delete;
    CNonOwningFileReader& operator=(const CNonOwningFileReader&) = delete;

    size_t Read(char* pch, size_t maxSize)
    {
        size_t read = fread(pch, 1, maxSize, mFile);

        if (read == 0 && !EndOfStream())
        {
            throw std::ios_base::failure{"CNonOwningFileReader::Read: fread failed"};
        }

        return read;
    }

    bool EndOfStream() const
    {
        return feof(mFile);
    }

private:
    FILE* mFile;
};

/**
 * Stream wrapper for cases where we have a data Reader and know exactly how
 * much data we want to read from it.
 */
template<typename Reader>
class CSyncFixedSizeStream : public CForwardReadonlyStream, private Reader
{
public:
    CSyncFixedSizeStream(size_t size, Reader&& reader)
        : Reader{std::move(reader)}
        , mSize{size}
    {/**/}

    bool EndOfStream() const override {return mSize == mConsumed;}
    CSpan Read(size_t maxSize) override
    {
        // it's not feasible to try and read 0 bytes
        assert(maxSize > 0);

        if(EndOfStream())
        {
            return {};
        }

        size_t maxConsumable = std::min(mSize - mConsumed, maxSize);

        mBuffer.resize(maxSize);

        size_t read =
            Reader::Read(
                reinterpret_cast<char*>(mBuffer.data()),
                maxConsumable);

        mConsumed += read;

        return {mBuffer.data(), read};
    }

private:
    size_t mSize;
    std::vector<uint8_t> mBuffer;
    size_t mConsumed = 0u;
};


/**
 * Stream wrapper for cases where we have a data Reader and know exactly how
 * much data we want to read from it.
 */
template<typename Reader>
class CFixedSizeStream : public CForwardAsyncReadonlyStream, private Reader
{
public:
    CFixedSizeStream(size_t size, Reader&& reader)
        : Reader{std::move(reader)}
        , mSize{size}
    {/**/}

    bool EndOfStream() const override {return mSize == mConsumed;}
    CSpan ReadAsync(size_t maxSize) override
    {
        // it's not feasible to try and read 0 bytes
        assert(maxSize > 0);

        // once read request has started the requested size may not change as an
        // async read request requires mBuffer stability until the end of
        // request or Reader destruction
        size_t maxConsumable = std::min(mSize - mConsumed, maxSize);
        assert(mPendingReadSize == 0 || mPendingReadSize == maxConsumable);

        if(mSize > mConsumed)
        {
            if(!mPendingReadSize)
            {
                mPendingReadSize = maxConsumable;
                mBuffer.resize(mPendingReadSize);
            }

            size_t read =
                Reader::Read(
                    reinterpret_cast<char*>(mBuffer.data()),
                    mPendingReadSize);

            if(read > 0)
            {
                // read request has finished
                mPendingReadSize = 0;
                mConsumed += read;
            }

            return {mBuffer.data(), read};
        }
        else
        {
            return {};
        }
    }

private:
    size_t mSize;
    std::vector<uint8_t> mBuffer;
    size_t mConsumed = 0u;
    size_t mPendingReadSize = 0u;
};

/**
 * Stream wrapper for std::vector<uint8_t>
 */
class CVectorStream : public CForwardAsyncReadonlyStream
{
public:
    CVectorStream(std::vector<uint8_t>&& data)
        : mData{std::move(data)}
    {/**/}

    bool EndOfStream() const override {return mData.size() == mConsumed;}
    CSpan ReadAsync(size_t maxSize) override
    {
        if(mData.size() > mConsumed)
        {
            size_t consume = std::min(mData.size() - mConsumed, maxSize);
            const uint8_t* start = mData.data() + mConsumed;
            mConsumed += consume;

            return {start, consume};
        }
        else
        {
            return {};
        }
    }

private:
    std::vector<uint8_t> mData;
    size_t mConsumed = 0u;
};

/**
 * Stream wrapper for std::shared_ptr<const std::vector<uint8_t>>
 */
class CSharedVectorStream : public CForwardAsyncReadonlyStream
{
public:
    CSharedVectorStream(std::shared_ptr<const std::vector<uint8_t>> data)
        : mData{std::move(data)}
    {/**/}

    bool EndOfStream() const override {return mData->size() == mConsumed;}
    CSpan ReadAsync(size_t maxSize) override
    {
        if(mData->size() > mConsumed)
        {
            size_t consume = std::min(mData->size() - mConsumed, maxSize);
            const uint8_t* start = mData->data() + mConsumed;
            mConsumed += consume;

            return {start, consume};
        }
        else
        {
            return {};
        }
    }

private:
    std::shared_ptr<const std::vector<uint8_t>> mData;
    size_t mConsumed = 0u;
};

}

#endif // SV_STREAMS_H

