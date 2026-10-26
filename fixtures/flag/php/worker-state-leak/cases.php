self::$currentUser = $request->user();
static::$tenant = $request->header('X-Tenant-ID');
self::$currentRequest = $request;
static::$user = $auth->getUser();
public static $currentUser;
