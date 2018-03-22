<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Url\Business\Redirect;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\LocaleTransfer;
use Generated\Shared\Transfer\UrlRedirectTransfer;
use Generated\Shared\Transfer\UrlTransfer;
use Orm\Zed\Locale\Persistence\SpyLocale;
use Orm\Zed\Url\Persistence\Base\SpyUrlRedirectQuery;
use Orm\Zed\Url\Persistence\SpyUrl;
use Orm\Zed\Url\Persistence\SpyUrlQuery;
use Orm\Zed\Url\Persistence\SpyUrlRedirect;
use Spryker\Zed\Url\Business\UrlFacade;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Url
 * @group Business
 * @group Redirect
 * @group RedirectChainInjectionTest
 * Add your own group annotations below this line
 */
class RedirectChainInjectionTest extends Unit
{
    /**
     * @var \Spryker\Zed\Url\Business\UrlFacade
     */
    protected $urlFacade;

    /**
     * @return void
     */
    public function setUp()
    {
        parent::setUp();

        $this->urlFacade = new UrlFacade();
    }

    /**
     * @return void
     */
    public function testAvoidRedirectChainByCreatingRedirectToAlreadyRedirectedUrlOnRedirectCreate()
    {
        $localeTransfer = $this->prepareTestData();
        $bazUrlRedirectTransfer = $this->createUrlRedirectTransfer('/test-baz', '/test-bar', $localeTransfer->getIdLocale());

        $bazUrlRedirectTransfer = $this->urlFacade->createUrlRedirect($bazUrlRedirectTransfer);

        $actualRedirectEntity = SpyUrlRedirectQuery::create()->findOneByIdUrlRedirect($bazUrlRedirectTransfer->getIdUrlRedirect());

        $this->assertEquals(
            '/test-foo',
            $actualRedirectEntity->getToUrl(),
            'Redirect to already redirected target should resolve in target\'s target.'
        );
    }

    /**
     * @return void
     */
    public function testAvoidRedirectChainByCreatingRedirectToAlreadyRedirectedUrlOnRedirectUpdate()
    {
        $localeTransfer = $this->prepareTestData();

        $this->createUrlRedirectEntity('/test/url-1', '/test/url-2', $localeTransfer->getIdLocale());
        $urlEntity = $this->createUrlRedirectEntity('/test/url-3', '/test/url-4', $localeTransfer->getIdLocale());

        $urlRedirectTransfer = $this->createUrlRedirectTransfer('/test/url-4', '/test/url-1', $localeTransfer->getIdLocale());
        $urlRedirectTransfer
            ->setIdUrlRedirect($urlEntity->getSpyUrlRedirect()->getIdUrlRedirect())
            ->getSource()->setIdUrl($urlEntity->getIdUrl());

        $this->urlFacade->updateUrlRedirect($urlRedirectTransfer);

        $this->assertTrue($this->hasUrlRedirect('/test/url-1', '/test/url-2'), 'Original redirect should have been persisted and unmodified.');
        $this->assertTrue($this->hasUrlRedirect('/test/url-4', '/test/url-2'), 'Manually updated redirect should point to the final redirect target.');
        $this->assertTrue($this->hasUrlRedirect('/test/url-3', '/test/url-2'), 'Manually updated redirect should have created new redirect from its original url.');
    }

    /**
     * @return \Generated\Shared\Transfer\LocaleTransfer
     */
    protected function prepareTestData()
    {
        $localeEntity = $this->createLocaleEntity();
        $localeTransfer = new LocaleTransfer();
        $localeTransfer->fromArray($localeEntity->toArray(), true);

        $urlEntity = $this->createUrlEntity($localeEntity, '/test-foo');
        $this->createUrlRedirectEntity('/test-bar', $urlEntity->getUrl(), $localeEntity->getIdLocale());

        return $localeTransfer;
    }

    /**
     * @return \Orm\Zed\Locale\Persistence\SpyLocale
     */
    protected function createLocaleEntity()
    {
        $localeEntity = new SpyLocale();
        $localeEntity
            ->setLocaleName('ab_CD')
            ->save();

        return $localeEntity;
    }

    /**
     * @param \Orm\Zed\Locale\Persistence\SpyLocale $localeEntity
     * @param string $url
     *
     * @return \Orm\Zed\Url\Persistence\SpyUrl
     */
    protected function createUrlEntity(SpyLocale $localeEntity, $url)
    {
        $urlEntity = new SpyUrl();
        $urlEntity
            ->setUrl($url)
            ->setFkLocale($localeEntity->getIdLocale())
            ->save();

        return $urlEntity;
    }

    /**
     * @param \Orm\Zed\Url\Persistence\SpyUrl $urlEntity
     *
     * @return \Generated\Shared\Transfer\UrlTransfer
     */
    protected function mapEntityToTransfer(SpyUrl $urlEntity)
    {
        $urlTransfer = new UrlTransfer();
        $urlTransfer->fromArray($urlEntity->toArray(), true);

        return $urlTransfer;
    }

    /**
     * @param string $source
     * @param string $target
     * @param int $idLocale
     *
     * @return \Orm\Zed\Url\Persistence\SpyUrl
     */
    protected function createUrlRedirectEntity($source, $target, $idLocale)
    {
        $redirectEntity = new SpyUrlRedirect();
        $redirectEntity
            ->setToUrl($target)
            ->save();

        $urlEntity = new SpyUrl();
        $urlEntity
            ->setUrl($source)
            ->setFkResourceRedirect($redirectEntity->getIdUrlRedirect())
            ->setFkLocale($idLocale)
            ->save();

        return $urlEntity;
    }

    /**
     * @param string $sourceUrl
     * @param string $targetUrl
     * @param int $idLocale
     *
     * @return \Generated\Shared\Transfer\UrlRedirectTransfer
     */
    protected function createUrlRedirectTransfer($sourceUrl, $targetUrl, $idLocale)
    {
        $sourceUrlTransfer = new UrlTransfer();
        $sourceUrlTransfer
            ->setUrl($sourceUrl)
            ->setFkLocale($idLocale);

        $urlRedirectTransfer = new UrlRedirectTransfer();
        $urlRedirectTransfer
            ->setSource($sourceUrlTransfer)
            ->setToUrl($targetUrl)
            ->setStatus(123);

        return $urlRedirectTransfer;
    }

    /**
     * @param string $sourceUrl
     * @param string $targetUrl
     *
     * @return bool
     */
    protected function hasUrlRedirect($sourceUrl, $targetUrl)
    {
        $count = SpyUrlQuery::create()
            ->useSpyUrlRedirectQuery()
                ->filterByToUrl($targetUrl)
            ->endUse()
            ->filterByUrl($sourceUrl)
            ->count();

        return $count > 0;
    }
}
