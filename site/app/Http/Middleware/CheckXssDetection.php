<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Symfony\Component\Process\Process;

class CheckXssDetection
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        $post = $request->all();
        $checkString = '';
        if (!empty($post))
            $checkString = urlencode(json_encode($post));
        $output = null;
        $retval = null;
        switch (PHP_OS) {
            case "WINNT":
                $output = self::execute(`python.exe -W ignore C:\Dev\Projects\ML-XSS-Detection-main\xss\classifiers.py --xss_detection '{$checkString}'`);
                break;
            case "Darwin":
                $output = self::execute("python3 -W ignore '/Users/berat/Documents/Projects/XSS-Detector-ML/xss/classifiers.py' --xss_detection '{$checkString}'");
                return response()->json([$output]);
                break;
            case "Linux":
                $output = shell_exec("python3 -W ignore /Users/berat/Documents/Projects/XSS-Detector-ML/xss/classifiers.py --xss_detection '{$checkString}'");
                break;
            default:
                $output = shell_exec("python3 -W ignore /Users/berat/Documents/Projects/XSS-Detector-ML/xss/classifiers.py --xss_detection '{$checkString}'");
                break;
        }
        if (strpos($output, 'reject') !== false) {
            return response()->json(['error' => 'XSS Detected'], 403);
        }
        return $next($request);
    }
    private static function macOSexecute($command)
    {
        $process = shell_exec($command);
        return $process;
    }

    private static function execute($cmd): string
    {
        $process = Process::fromShellCommandline($cmd);

        $processOutput = '';

        $captureOutput = function ($type, $line) use (&$processOutput) {
            $processOutput .= $line;
        };

        $process->setTimeout(null)
            ->run($captureOutput);

        if ($process->getExitCode()) {
            $exception = new Exception('Shell Error');
        }

        return $processOutput;
    }
}
