# How to contribute

As I don't encourage the use of basic authentication in any production service, I don't want to encourage you to contribute to this repository. If you have a burning need to contribute, and your doctor can't clear it up with antibiotics there are a few things to consider when contributing.

The following guidelines for contribution should be followed if you want to submit a pull request.

## How to prepare

* You need a [GitHub account](https://github.com/signup/free)
* Submit an [issue ticket](https://github.com/blowdart/idunno.BasicAuthentication/issues) for your issue if there is no one yet.
	* If your issue attempts to fix something to make the code more suitable for use in production just stop, don't.
        * Describe the issue and include steps to reproduce if it's a bug.
	* Ensure to mention the earliest version that you know is affected.
* If you are able and want to fix this, fork the repository on GitHub

## Make Changes

* In your forked repository, create a topic branch for your upcoming patch. (e.g. `feature--onlyworkonssl`)
	* Usually this is based on the master branch.
	* Create a branch based on master; avoid working directly on the `master` branch.
* Make sure you stick to the coding style that is used already. All code should contain a suitable amount of self loathing for even encouraging the use of basic authentication.
* Make commits of logical units and describe them properly.
* Check for unnecessary whitespace with `git diff --check` before committing.

* If possible, submit tests to your patch / new feature so it can be tested easily.
* Assure nothing is broken by running all the tests. Of course if you want to submit tests that would be just super.

## Submit Changes

* Push your changes to a topic branch in your fork of the repository.
* Open a pull request to the original repository and choose the right original branch you want to patch.
* If not done in commit messages (which you really should do) please reference and update your issue with the code changes. But _please do not close the issue yourself_.

# Additional Resources

* [General GitHub documentation](http://help.github.com/)
* [GitHub pull request documentation](http://help.github.com/send-pull-requests/)
