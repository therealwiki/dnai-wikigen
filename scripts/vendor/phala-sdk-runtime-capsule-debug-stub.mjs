function disabledDebug() {
  const logger = () => {};
  logger.enabled = false;
  logger.extend = disabledDebug;
  return logger;
}

disabledDebug.enable = () => {};
disabledDebug.disable = () => {};
disabledDebug.enabled = () => false;
disabledDebug.humanize = () => "0ms";

export default disabledDebug;
