#pragma once

#include <memory>
#include <iostream>
#include <ctime>

#ifdef __unix
#include <unistd.h>
#endif

class NecroLog
{
public:
	enum class Level {Fatal, Error, Warning, Info, Debug};
	class LogContext
	{
	public:
		LogContext() : file(nullptr), line(0) {}
		LogContext(const char *file_name, int line_number)
			: file(file_name), line(line_number) {}

		const char *file;
		int line;
	};
public:
	NecroLog(std::ostream &os, Level level, LogContext &&log_context)
	{
		m_necro = std::make_shared<Necro>(os, level, std::move(log_context));
	}

	template<typename T>
	NecroLog& operator<<(const T &v) {m_necro->maybeSpace(); m_necro->m_os << v; return *this;}
	NecroLog& nospace() {m_necro->setSpace(false); return *this;}

	static NecroLog create(std::ostream &os, Level level, LogContext &&log_context)
	{
		return NecroLog(os, level, std::move(log_context));
	}
private:
	class Necro {
		friend class NecroLog;
public:
		Necro(std::ostream &os, NecroLog::Level level, LogContext &&log_context)
			: m_os(os)
			, m_level(level)
			, m_logContext(std::move(log_context))
		{
#ifdef __unix
			m_isTTI = true;//(&m_os == &std::clog) && ::isatty(STDERR_FILENO);
#endif
		}
		~Necro()
		{
			epilog();
			m_os << std::endl;
			m_os.flush();
		}

		void setSpace(bool b) {m_isSpace = b;}
	private:
		void maybeSpace()
		{
			if(m_firstRun) {
				m_firstRun = false;
				prolog();
			}
			else {
				if(m_isSpace) {
					m_os << ' ';
				}
			}
		}

		std::string moduleFromFileName(const char *file_name)
		{
			//if(s_logLongFileNames)
			//	return std::string(file_name);
			std::string ret(file_name);
			auto ix = ret.find_last_of('/');
		#ifndef __unix
			if(ix == std::string::npos)
				ix = ret.find_last_of('\\');
		#endif
			if(ix != std::string::npos)
				ret = ret.substr(ix + 1);
			return ret;
		}

		enum TTYColor {Black=0, Red, Green, Yellow, Blue, Magenta, Cyan, White};

		std::ostream& setTtyColor(TTYColor color, bool bright = false, bool bg_color = false)
		{
			if(m_isTTI)
				m_os << "\033[" << (bright? '1': '0') << ';' << (bg_color? '4': '3') << char('0' + color) << 'm';
			return m_os;
		}
		void prolog()
		{
			std::time_t t = std::time(nullptr);
			std::tm *tm = std::gmtime(&t); /// gmtime is not thread safe!!!
			char buffer[80] = {0};
			std::strftime(buffer, sizeof(buffer),"%Y-%m-%dT%H:%M:%S", tm);
			setTtyColor(TTYColor::Green, true) << std::string(buffer);
			setTtyColor(TTYColor::Yellow, true) << '[' << moduleFromFileName(m_logContext.file) << ':' << m_logContext.line << "]";
			switch(m_level) {
			case NecroLog::Level::Fatal:
				setTtyColor(TTYColor::Red, true) << "|F|";
				break;
			case NecroLog::Level::Error:
				setTtyColor(TTYColor::Red, true) << "|E|";
				break;
			case NecroLog::Level::Warning:
				setTtyColor(TTYColor::Magenta, true) << "|W|";
				break;
			case NecroLog::Level::Info:
				setTtyColor(TTYColor::Cyan, true) << "|I|";
				break;
			case NecroLog::Level::Debug:
				setTtyColor(TTYColor::White, false) << "|D|";
				break;
			default:
				setTtyColor(TTYColor::Red, true) << "|?|";
				break;
			};
			m_os << " ";
		}
		void epilog()
		{
			if(m_isTTI)
				m_os << "\33[0m";
		}
	private:
		std::ostream &m_os;
		NecroLog::Level m_level;
		LogContext m_logContext;
		bool m_isSpace = true;
		bool m_firstRun = true;
		bool m_isTTI = false;
	};
private:
	std::shared_ptr<Necro> m_necro;
};

#define nDebug() NecroLog::create(std::clog, NecroLog::Level::Debug, NecroLog::LogContext(__FILE__, __LINE__))
#define nInfo() NecroLog::create(std::clog, NecroLog::Level::Info, NecroLog::LogContext(__FILE__, __LINE__))
#define nWarning() NecroLog::create(std::clog, NecroLog::Level::Warning, NecroLog::LogContext(__FILE__, __LINE__))
#define nError() NecroLog::create(std::clog, NecroLog::Level::Error, NecroLog::LogContext(__FILE__, __LINE__))
