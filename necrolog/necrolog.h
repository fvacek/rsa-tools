#pragma once

#include <vector>
#include <map>
#include <memory>
#include <iostream>
#include <ctime>
#include <algorithm>

#ifdef __unix
#include <unistd.h>
#endif

class NecroLog
{
	friend class Necro;
public:
	enum class Level {Fatal, Error, Warning, Info, Debug};
	class LogContext
	{
	public:
		LogContext() : file(nullptr), line(0) {}
		LogContext(const char *file_name, int line_number, const char *topic)
			: file(file_name), line(line_number), topic(topic) {}

		const char *file;
		int line;
		const char *topic;
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
	static bool shouldLog(Level level, const LogContext &context)
	{
		const std::map<std::string, Level> &tresholds = globalOptions().tresholds;
		if(tresholds.empty())
			return (level <= Level::Info); // default log level

		const char *ctx_topic = (context.topic && context.topic[0])? context.topic: context.file;
		for (size_t j = 0; ctx_topic[j]; ++j) {
			for(const auto &pair : tresholds) {
				const std::string &g_topic = pair.first;
				size_t i;
				for (i = 0; i < g_topic.size() && ctx_topic[i+j]; ++i) {
					if(tolower(ctx_topic[i+j]) != g_topic[i])
						break;
				}
				if(i == g_topic.size())
					return (level <= pair.second);
			}
		}
		return false;
	}
	static std::vector<std::string> setCLIOptions(int argc, char *argv[])
	{
		using namespace std;
		std::vector<string> ret;
		for(int i=1; i<argc; i++) {
			string s = argv[i];
			if(s == "-lfn" || s == "--log-long-file-names") {
				i++;
				globalOptions().logLongFileNames = true;
			}
			else if(s == "-d" || s == "-v" || s == "--verbose") {
				i++;
				string tresholds = (i < argc)? argv[i]: string();
				if(!tresholds.empty() && tresholds[0] == '-') {
					i--;
					tresholds = ":D";
				}
				{
					// split on ','
					size_t pos = 0;
					while(true) {
						size_t pos2 = tresholds.find_first_of(',', pos);
						string topic_level = (pos2 == string::npos)? tresholds.substr(pos): tresholds.substr(pos, pos2 - pos);
						if(!s.empty()) {
							auto ix = topic_level.find(':');
							Level level = Level::Debug;
							std::string topic = topic_level;
							if(ix != std::string::npos) {
								std::string s = topic_level.substr(ix + 1, 1);
								char l = s.empty()? 'D': toupper(s[0]);
								topic = topic_level.substr(0, ix);
								switch(l) {
								case 'D': level = Level::Debug; break;
								case 'W': level = Level::Warning; break;
								case 'E': level = Level::Error; break;
								case 'I':
								default: level = Level::Info; break;
								}
							}
							std::transform(topic.begin(), topic.end(), topic.begin(), ::tolower);
							globalOptions().tresholds[topic] = level;
						}
						if(pos2 == string::npos)
							break;
						pos = pos2 + 1;
					}
				}
			}
			else {
				ret.push_back(s);
			}
		}
		ret.insert(ret.begin(), argv[0]);
		return ret;
	}
	static const char *cliHelp()
	{
		return
			"-lfn, --log-long-file-names\n"
			"\tLog long file names\n"
			"-d, -v, --verbose [<pattern>]:[D|I|W|E]\n"
			"\tSet files or topics log treshold\n"
			"\tset treshold for all files or topics containing pattern to treshold D|I|W|E\n"
			"\twhen pattern is not set, set treshold for any filename or topic\n"
			"\twhen treshold is not set, set treshold D (Debug) for all files or topics containing pattern\n"
			"\twhen nothing is not set, set treshold D (Debug) for all files or topics\n"
			"\tExamples:\n"
			"\t\t-d\t\tset treshold D (Debug) for all files or topics\n"
			"\t\t-d :W\t\tset treshold W (Warning) for all files or topics\n"
			"\t\t-d foo,bar\t\tset treshold D for all files or topics containing 'foo' or 'bar'\n"
			"\t\t-d bar:W\tset treshold W (Warning) for all files or topics containing 'bar'\n"
			;
	}
private:
	struct Options
	{
		std::map<std::string, Level> tresholds;
		bool logLongFileNames = false;
	};
	static inline Options& globalOptions()
	{
		static Options global_options;
		return global_options;
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
			if(NecroLog::globalOptions().logLongFileNames)
				return std::string(file_name);

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
			setTtyColor(TTYColor::Green, false) << std::string(buffer);
			setTtyColor(TTYColor::Yellow, false) << '[' << moduleFromFileName(m_logContext.file) << ':' << m_logContext.line << "]";
			if(m_logContext.topic && m_logContext.topic[0]) {
				setTtyColor(TTYColor::White, true) << '(' << m_logContext.topic << ")";
			}
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

#define nCDebug(topic) for(bool en = NecroLog::shouldLog(NecroLog::Level::Debug, NecroLog::LogContext(__FILE__, __LINE__, topic)); en; en = false) NecroLog::create(std::clog, NecroLog::Level::Debug, NecroLog::LogContext(__FILE__, __LINE__, topic))
#define nCInfo(topic) for(bool en = NecroLog::shouldLog(NecroLog::Level::Info, NecroLog::LogContext(__FILE__, __LINE__, topic)); en; en = false) NecroLog::create(std::clog, NecroLog::Level::Info, NecroLog::LogContext(__FILE__, __LINE__, topic))
#define nCWarning(topic) for(bool en = NecroLog::shouldLog(NecroLog::Level::Warning, NecroLog::LogContext(__FILE__, __LINE__, topic)); en; en = false) NecroLog::create(std::clog, NecroLog::Level::Warning, NecroLog::LogContext(__FILE__, __LINE__, topic))
#define nCError(topic) for(bool en = NecroLog::shouldLog(NecroLog::Level::Error, NecroLog::LogContext(__FILE__, __LINE__, topic)); en; en = false) NecroLog::create(std::clog, NecroLog::Level::Error, NecroLog::LogContext(__FILE__, __LINE__, topic))

#define nDebug() nCDebug("")
#define nInfo() nCInfo("")
#define nWarning() nCWarning("")
#define nError() nCError("")
